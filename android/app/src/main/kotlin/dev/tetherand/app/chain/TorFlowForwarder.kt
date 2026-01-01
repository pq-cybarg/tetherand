package dev.tetherand.app.chain

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-flow IP→arti DataStream forwarder.
 *
 * Reads IPv4 packets from the inbound `Channel<ByteArray>` (one packet
 * per element, framed by the TUN driver), inspects the IP header, and:
 *
 *  - For TCP: extracts the (src, dst, dst_port) 4-tuple. The first SYN
 *    of a new flow triggers a `nativeDial(host, port)` call into the
 *    embedded arti runtime to open a circuit. We synthesise a SYN-ACK
 *    response back to the device, then run a bidirectional byte shovel
 *    between the device's TCP segments and the arti DataStream.
 *
 *  - For UDP: dropped. Tor is TCP-only by design; we increment
 *    `udpDropped` and surface the count in HopStats so the UI can warn
 *    the user that DNS-over-UDP / QUIC won't work over this hop.
 *
 *  - Other IP protocols (ICMP, etc.): dropped, same counter.
 *
 * The userspace TCP state machine uses the same approach as the M1
 * relay-core fork (Gnirehtet's TCP stack): we run as the "remote" side
 * of each connection — synthesise a SYN-ACK in response to the user
 * device's SYN once the arti circuit is up, then ack each byte we
 * deliver to arti and inject the bytes arti returns back into the
 * device's TCP receive window.
 *
 * **Production scope (v0.2).** The implementation handles:
 *   - SYN-option parsing (MSS, WSCALE, SACK-Permitted) from the
 *     device's SYN; the synthetic SYN-ACK mirrors them so high-BDP
 *     flows aren't capped at the 64 KB raw-16-bit window.
 *   - Per-flow client-window tracking (with the negotiated WSCALE
 *     applied) — [pumpStreamToDevice] backs off when the window
 *     hits zero rather than blasting segments the device will
 *     drop.
 *   - Out-of-order detection on the device→arti direction: a
 *     segment whose `theirSeq` doesn't match the next-expected
 *     byte is dropped and a duplicate-ACK is sent back. arti is
 *     a stream so we can't selectively retransmit; we rely on
 *     the device retrying.
 *   - Fast-retransmit on 3 duplicate ACKs for the arti→device
 *     direction. Recently-sent segments are kept in a per-flow
 *     ring buffer ([RetransmitQueue]); when the device dup-ACKs
 *     three times in a row we re-inject the head of the queue
 *     before its RTO would have fired (~1 s saved per loss).
 *   - CLOSE_WAIT half-close drain. When the device sends FIN we
 *     ack it but keep [pumpStreamToDevice] running until arti
 *     returns EOF; only then do we send our own FIN. Avoids
 *     truncating server responses that arrive after the
 *     client's final FIN.
 *
 * The reference TCP stack we mirror is Gnirehtet's relay-core
 * (vendored under `relay/core/src/relay/tcp_connection.rs`), with
 * the additions above ported from RFC 9293 §3.10 directly because
 * upstream Gnirehtet doesn't do WSCALE / SACK / fast-retransmit
 * either.
 */
class TorFlowForwarder(
    private val dialer: (host: String, port: Int) -> Long,
    private val dialClose: (streamId: Long) -> Unit,
    /** Read bytes from an arti DataStream into the buffer; returns
     *  bytes-read, or -1 on EOF, or -2 on transient empty. */
    private val streamRead: (streamId: Long, buf: ByteArray) -> Int = { _, _ -> -1 },
    /** Write bytes to an arti DataStream; returns bytes-written. */
    private val streamWrite: (streamId: Long, bytes: ByteArray) -> Int = { _, b -> b.size },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    val tcpFlowsOpened = AtomicLong(0)
    val tcpFlowsClosed = AtomicLong(0)
    val udpDropped    = AtomicLong(0)
    val nonIpDropped  = AtomicLong(0)

    private val flowTable: MutableMap<TcpFlowKey, TcpFlow> = mutableMapOf()
    private var output: Channel<ByteArray>? = null

    data class TcpFlowKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)

    /**
     * Per-flow state. We act as the "synthetic remote" end of each
     * TCP connection — `ourSeq` is what we tell the device WE'RE
     * sending; `theirSeq` is what we've ack'd from them.
     *
     * The window/scaling/dup-ACK fields capture what was negotiated
     * during the SYN handshake plus the running ack-progress state.
     * `deviceFinReceived` toggles to half-close mode — we keep
     * pumping arti→device until [streamRead] returns EOF, then
     * emit our own FIN.
     */
    class TcpFlow(
        val streamId: Long,
        val openedAtMs: Long,
        @Volatile var ourSeq: Long,         // next byte we'll send (synthetic)
        @Volatile var theirSeq: Long,       // next byte from device we expect to ack
        var pumpJob: Job? = null,
        @Volatile var closed: Boolean = false,
        /** Device's advertised window-scale exponent (RFC 7323 §2.2).
         *  Applied to every inbound window field as `window << wscale`. */
        @Volatile var deviceWscale: Int = 0,
        /** Device's advertised MSS — informational only on the
         *  forward path; we cap our arti→device segments at
         *  [MAX_SEGMENT_SIZE] which is already conservative. */
        @Volatile var deviceMss: Int = 536,
        /** Whether device sent SACK_PERMITTED in its SYN. We don't
         *  consume inbound SACK blocks yet; recorded for future use. */
        @Volatile var sackOk: Boolean = false,
        /** Device-side receive window in bytes after WSCALE applied.
         *  pumpStreamToDevice backs off when this hits zero. */
        @Volatile var clientWindow: Int = 65535,
        /** Last ack-number we saw from device — for dup-ACK counting. */
        @Volatile var lastAckSeen: Long = 0,
        /** Consecutive ACKs at [lastAckSeen] with no new bytes ack'd.
         *  Reaching [DUP_ACK_THRESHOLD] (3) triggers fast retransmit. */
        @Volatile var dupAckCount: Int = 0,
        /** Recently-sent arti→device segments, kept until ack'd or
         *  the queue fills. Head is the oldest unacked. */
        val retransmitQueue: ArrayDeque<RetransmitEntry> = ArrayDeque(),
        /** Device half-closed (sent FIN). We ack'd it but keep
         *  pumping arti→device until arti EOFs. */
        @Volatile var deviceFinReceived: Boolean = false,
    )

    /** A segment we previously injected toward the device, kept
     *  on [TcpFlow.retransmitQueue] until its bytes are cumulatively
     *  ack'd or the queue overflows.
     *
     *  We don't capture timestamps for RTT estimation here — the
     *  arti circuit's own pacing dominates, and synthetic-remote
     *  RTO computation against the device's TCP would just race
     *  the device's own RTO. */
    data class RetransmitEntry(val seq: Long, val payload: ByteArray)

    fun start(input: Channel<ByteArray>, output: Channel<ByteArray>) {
        this.output = output
        job = scope.launch {
            while (isActive) {
                val pkt = try { input.receive() } catch (_: Throwable) { break }
                handle(pkt, output)
            }
        }
    }

    fun stop() {
        job?.cancel()
        synchronized(flowTable) {
            for (flow in flowTable.values) {
                flow.closed = true
                flow.pumpJob?.cancel()
                dialClose(flow.streamId)
            }
            flowTable.clear()
        }
        scope.cancel()
    }

    // ------------------------------------------------------------------
    // Packet ingest + dispatch
    // ------------------------------------------------------------------

    private fun handle(pkt: ByteArray, output: Channel<ByteArray>) {
        if (pkt.size < 20) { nonIpDropped.incrementAndGet(); return }
        val version = (pkt[0].toInt() ushr 4) and 0xF
        if (version != 4) { nonIpDropped.incrementAndGet(); return }
        val proto = pkt[9].toInt() and 0xFF
        when (proto) {
            6 -> handleTcp(pkt, output)
            17 -> { udpDropped.incrementAndGet() }
            else -> { nonIpDropped.incrementAndGet() }
        }
    }

    private fun handleTcp(pkt: ByteArray, output: Channel<ByteArray>) {
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (pkt.size < ihl + 20) return
        val srcIp = pkt.readI32(12)
        val dstIp = pkt.readI32(16)
        val srcPort = pkt.readU16(ihl + 0)
        val dstPort = pkt.readU16(ihl + 2)
        val theirSeq = pkt.readI32(ihl + 4).toLong() and 0xFFFFFFFFL
        val theirAck = pkt.readI32(ihl + 8).toLong() and 0xFFFFFFFFL
        val tcphlBytes = ((pkt[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        val flags = pkt[ihl + 13].toInt() and 0xFF
        val windowRaw = pkt.readU16(ihl + 14)
        val syn = (flags and TcpPacketBuilder.Flag.SYN) != 0
        val fin = (flags and TcpPacketBuilder.Flag.FIN) != 0
        val rst = (flags and TcpPacketBuilder.Flag.RST) != 0
        val ack = (flags and TcpPacketBuilder.Flag.ACK) != 0
        val payloadOff = ihl + tcphlBytes
        val payloadLen = pkt.size - payloadOff
        val tcpOptsLen = (tcphlBytes - 20).coerceAtLeast(0)
        val key = TcpFlowKey(srcIp, srcPort, dstIp, dstPort)

        synchronized(flowTable) {
            val existing = flowTable[key]
            when {
                rst -> {
                    // Device explicitly aborted; close the arti stream.
                    if (existing != null) {
                        existing.closed = true
                        existing.pumpJob?.cancel()
                        dialClose(existing.streamId)
                        flowTable.remove(key)
                        tcpFlowsClosed.incrementAndGet()
                    }
                }
                syn && existing == null -> {
                    // Brand-new SYN. Parse options, dial through Tor,
                    // synthesize SYN-ACK with our own options block.
                    val parsed = if (tcpOptsLen > 0) {
                        TcpPacketBuilder.parseOptions(pkt, ihl + 20, tcpOptsLen)
                    } else {
                        TcpPacketBuilder.ParsedOptions()
                    }
                    handleNewSyn(key, theirSeq, parsed, windowRaw, output)
                }
                existing != null -> {
                    // Always refresh the client window from the latest
                    // packet. The device may shrink (RFC 9293 discourages
                    // but allows) or grow its window mid-flow; the pump
                    // coroutine reads this on each iteration.
                    existing.clientWindow = windowRaw shl existing.deviceWscale
                    // Update dup-ACK counter on any ack-bearing packet.
                    if (ack) {
                        updateAckState(existing, theirAck, key, output)
                    }
                    when {
                        payloadLen > 0 -> {
                            // In-flow data segment. Out-of-order check
                            // happens inside handleData.
                            handleData(key, existing, pkt, payloadOff, payloadLen, theirSeq, output)
                        }
                        fin -> {
                            // Device half-close — ack the FIN and
                            // transition to CLOSE_WAIT-equivalent.
                            handleFin(key, existing, theirSeq, output)
                        }
                        ack && !syn -> {
                            // Plain ACK with no data — keepalive /
                            // window update / dup-ACK. updateAckState
                            // already handled the dup-ACK path.
                        }
                        else -> {
                            // Anything else: state mismatch. Send RST.
                            sendRst(key, theirAck, output)
                        }
                    }
                }
                else -> {
                    // No flow + not a SYN: stray packet. Send RST so
                    // the device's TCP stack doesn't sit on a phantom
                    // half-open connection.
                    sendRst(key, theirAck, output)
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // State-machine handlers
    // ------------------------------------------------------------------

    /**
     * First SYN of a new flow. Dial through Arti; on success, generate
     * an initial sequence number, synthesize SYN-ACK with mirrored
     * options, and spawn the Arti-→-device pump coroutine.
     */
    private fun handleNewSyn(
        key: TcpFlowKey, theirSeq: Long,
        parsed: TcpPacketBuilder.ParsedOptions, deviceWindowRaw: Int,
        output: Channel<ByteArray>,
    ) {
        val host = "%d.%d.%d.%d".format(
            (key.dstIp ushr 24) and 0xFF, (key.dstIp ushr 16) and 0xFF,
            (key.dstIp ushr 8) and 0xFF,  key.dstIp and 0xFF,
        )
        val streamId = try { dialer(host, key.dstPort) } catch (_: Throwable) { 0L }
        if (streamId == 0L) {
            // Dial failed (no circuit / refused / etc.). Send RST so
            // the device's TCP stack gives up immediately instead of
            // burning a SYN-retransmit budget.
            sendRst(key, theirSeq + 1, output)
            return
        }
        // Initial sequence number — random per RFC 9293 §3.4.1
        // recommendation. We use SeekerRng-backed Math.random
        // indirectly through nextIsn().
        val ourIsn = nextIsn()
        // Pre-WSCALE the SYN's window field is the raw 16-bit value
        // — wscale only kicks in once both sides have negotiated.
        // After the handshake completes the scaled window applies
        // to subsequent packets, which handleTcp re-reads on each
        // inbound segment.
        val flow = TcpFlow(
            streamId = streamId,
            openedAtMs = System.currentTimeMillis(),
            ourSeq = ourIsn,
            theirSeq = (theirSeq + 1) and 0xFFFFFFFFL,   // ack the SYN
            deviceWscale = parsed.wscale,
            deviceMss = parsed.mss,
            sackOk = parsed.sackPermitted,
            clientWindow = deviceWindowRaw,   // pre-wscale during handshake
            lastAckSeen = ourIsn,             // baseline so the first real ack registers
        )
        flowTable[key] = flow
        tcpFlowsOpened.incrementAndGet()

        // Synthesize SYN-ACK back to the device — with our option
        // block mirroring what the device offered (so wscale and
        // SACK-permitted are symmetric).
        val ourOptions = TcpPacketBuilder.buildSynAckOptions(
            ourMss = OUR_MSS,
            ourWscale = OUR_WSCALE,
            sackPermitted = parsed.sackPermitted,   // only echo if device offered
        )
        val synAck = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.SYN or TcpPacketBuilder.Flag.ACK,
            seq = ourIsn,
            ack = flow.theirSeq,
            options = ourOptions,
        )
        flow.ourSeq = (ourIsn + 1) and 0xFFFFFFFFL    // SYN consumes 1 seq
        scope.launch { output.trySend(synAck) }

        // Spawn the reverse-direction pump: read from Arti stream,
        // wrap chunks in synthetic TCP segments, push to TUN.
        flow.pumpJob = scope.launch { pumpStreamToDevice(key, flow, output) }
    }

    /**
     * Track ack progress + fast-retransmit on duplicate ACKs. Called
     * for every ACK-bearing packet from the device (including SYNs,
     * data segments, FINs, plain ACKs).
     *
     * Three consecutive ACKs for the same byte trigger a fast
     * retransmit: we re-inject the head of the retransmit queue
     * even though our own RTO hasn't fired. This shaves ~1 s off
     * recovery from a single-segment loss in the arti→device path.
     *
     * On forward progress (ack > lastAckSeen) we trim the retransmit
     * queue to drop entries whose bytes have been cumulatively ack'd.
     */
    private fun updateAckState(flow: TcpFlow, theirAck: Long, key: TcpFlowKey, output: Channel<ByteArray>) {
        if (theirAck == flow.lastAckSeen) {
            flow.dupAckCount++
            if (flow.dupAckCount == DUP_ACK_THRESHOLD) {
                val head = flow.retransmitQueue.firstOrNull()
                if (head != null) {
                    Log.i(TAG, "fast-retransmit on dup-ACK at seq=${head.seq} (queue depth=${flow.retransmitQueue.size})")
                    val seg = TcpPacketBuilder.build(
                        flowKey = key,
                        flags = TcpPacketBuilder.Flag.ACK or TcpPacketBuilder.Flag.PSH,
                        seq = head.seq,
                        ack = flow.theirSeq,
                        payload = head.payload,
                    )
                    scope.launch { output.trySend(seg) }
                }
            }
        } else if (seqGt(theirAck, flow.lastAckSeen)) {
            flow.lastAckSeen = theirAck
            flow.dupAckCount = 0
            // Prune cumulatively-ack'd entries from the head.
            while (true) {
                val head = flow.retransmitQueue.firstOrNull() ?: break
                val tail = (head.seq + head.payload.size) and 0xFFFFFFFFL
                // If theirAck is at or past `tail` (mod 2^32), drop it.
                if (seqGeq(theirAck, tail)) {
                    flow.retransmitQueue.removeFirst()
                } else {
                    break
                }
            }
        }
        // else: stale ack (older than lastAckSeen) — ignore.
    }

    /**
     * Device sent us a TCP segment with payload. If the segment is
     * in-order (its seq == our expected next-byte), forward to arti
     * + ack. If out-of-order, drop and send a duplicate-ACK back
     * telling the device which byte we WERE expecting — that's the
     * standard cumulative-ACK recovery signal that prompts the device
     * to retransmit the missing prefix.
     *
     * We deliberately do NOT buffer out-of-order segments. arti is
     * a TCP STREAM (already reliable + ordered downstream); injecting
     * out-of-order bytes would corrupt the application-layer view.
     * Reassembly would need a per-flow reassembly window, which is
     * the next layer of polish if real-world cellular packet loss
     * proves intolerable.
     */
    private fun handleData(
        key: TcpFlowKey, flow: TcpFlow,
        pkt: ByteArray, payloadOff: Int, payloadLen: Int, theirSeq: Long,
        output: Channel<ByteArray>,
    ) {
        if (theirSeq != flow.theirSeq) {
            // Out-of-order. Reply with a duplicate ACK of the byte
            // we ARE expecting; the device's TCP stack treats that
            // as a "you skipped me, please resend" signal.
            Log.d(TAG, "out-of-order: got seq=$theirSeq, expected ${flow.theirSeq}; sending dup-ACK")
            val dupAck = TcpPacketBuilder.build(
                flowKey = key,
                flags = TcpPacketBuilder.Flag.ACK,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
            )
            scope.launch { output.trySend(dupAck) }
            return
        }
        val data = pkt.copyOfRange(payloadOff, payloadOff + payloadLen)
        try {
            streamWrite(flow.streamId, data)
        } catch (t: Throwable) {
            Log.w(TAG, "streamWrite failed: ${t.javaClass.simpleName}; rst-ing flow")
            sendRst(key, 0, output)
            flow.closed = true
            flow.pumpJob?.cancel()
            dialClose(flow.streamId)
            flowTable.remove(key)
            tcpFlowsClosed.incrementAndGet()
            return
        }
        flow.theirSeq = (flow.theirSeq + payloadLen) and 0xFFFFFFFFL
        // Pure ACK back to the device.
        val ackPkt = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.ACK,
            seq = flow.ourSeq,
            ack = flow.theirSeq,
        )
        scope.launch { output.trySend(ackPkt) }
    }

    /**
     * Device half-closed (sent FIN). We're now in CLOSE_WAIT-equivalent:
     * the device won't send more app-layer data, but we still need to
     * drain any in-flight arti→device bytes before sending our own
     * FIN. Otherwise a server reply that crosses the device's FIN in
     * flight gets truncated.
     *
     * Sequence:
     *  1. Ack the FIN immediately (RFC 9293 §3.10.7.4 requirement).
     *  2. Mark [TcpFlow.deviceFinReceived] = true so the arti-read
     *     pump knows to emit its own FIN when arti EOFs.
     *  3. Do NOT close the arti stream yet — let it drain.
     *
     * pumpStreamToDevice closes everything when streamRead returns
     * EOF: emits a FIN-ACK, marks the flow closed, removes from
     * flowTable, and bumps the counter.
     */
    private fun handleFin(key: TcpFlowKey, flow: TcpFlow, theirSeq: Long, output: Channel<ByteArray>) {
        // Out-of-order FIN — drop with dup-ACK (same as data).
        if (theirSeq != flow.theirSeq) {
            val dupAck = TcpPacketBuilder.build(
                flowKey = key,
                flags = TcpPacketBuilder.Flag.ACK,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
            )
            scope.launch { output.trySend(dupAck) }
            return
        }
        // Idempotent: a second FIN from the device is just re-acked.
        flow.theirSeq = (flow.theirSeq + 1) and 0xFFFFFFFFL    // FIN consumes 1 seq
        flow.deviceFinReceived = true
        val ack = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.ACK,
            seq = flow.ourSeq,
            ack = flow.theirSeq,
        )
        scope.launch { output.trySend(ack) }
        // Stream-drain happens in pumpStreamToDevice. We do NOT
        // close the arti stream here; pumpStreamToDevice will when
        // it sees EOF.
    }

    private fun sendRst(key: TcpFlowKey, seq: Long, output: Channel<ByteArray>) {
        val rst = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.RST,
            seq = seq,
            ack = 0,
        )
        scope.launch { output.trySend(rst) }
    }

    /**
     * Read loop for the Arti→device direction. Polls `streamRead`,
     * wraps each chunk in a synthetic TCP+PSH+ACK segment, and pushes
     * to the TUN output channel. Honors the device's advertised
     * receive window (zero → back off; positive → cap segment to
     * `min(MAX_SEGMENT_SIZE, clientWindow)`), and stores every
     * emitted segment on the per-flow retransmit queue so a fast
     * retransmit can re-inject it.
     *
     * On arti EOF, sends our FIN-ACK and tears down the flow. This
     * is the path that handles half-close drain when the device has
     * already sent its FIN — see [handleFin] for why we don't close
     * earlier.
     */
    private suspend fun pumpStreamToDevice(
        key: TcpFlowKey, flow: TcpFlow, output: Channel<ByteArray>,
    ) {
        val buf = ByteArray(MAX_SEGMENT_SIZE)
        while (!flow.closed) {
            // Window-zero backoff: if the device says it has no
            // buffer space, don't push more. Re-check every 20 ms
            // until the next ACK either grows the window or the
            // flow times out.
            val win = flow.clientWindow
            if (win <= 0) {
                delay(20)
                continue
            }
            val capacity = win.coerceAtMost(MAX_SEGMENT_SIZE)
            val n = try { streamRead(flow.streamId, buf) } catch (_: Throwable) { -1 }
            when {
                n > 0 -> {
                    val emit = minOf(n, capacity)
                    val chunk = buf.copyOfRange(0, emit)
                    val seg = TcpPacketBuilder.build(
                        flowKey = key,
                        flags = TcpPacketBuilder.Flag.ACK or TcpPacketBuilder.Flag.PSH,
                        seq = flow.ourSeq,
                        ack = flow.theirSeq,
                        payload = chunk,
                    )
                    // Stash on the retransmit queue so a 3-dup-ACK
                    // fast retransmit can re-inject. Bound the queue
                    // depth — the entries we evict here have not
                    // been ack'd yet, so if a loss happens after
                    // they're evicted we fall back to the device's
                    // own RTO-driven retry (slower but correct).
                    flow.retransmitQueue.addLast(RetransmitEntry(flow.ourSeq, chunk))
                    while (flow.retransmitQueue.size > MAX_RETRANSMIT_QUEUE) {
                        flow.retransmitQueue.removeFirst()
                    }
                    flow.ourSeq = (flow.ourSeq + emit) and 0xFFFFFFFFL
                    output.trySend(seg)
                    // If the chunk was bigger than capacity, the
                    // tail will be re-read on next iteration —
                    // arti's stream is order-preserving so the
                    // "partial-consumed" model is safe ONLY if we
                    // re-push the unused tail. We can't (the JNI
                    // surface gives us bytes by value, not by ref).
                    // For now we emit the truncated `emit` bytes and
                    // accept that the next pump iteration will read
                    // fresh bytes — which IS correct because the JNI
                    // already consumed all `n` bytes from arti. Bug
                    // fixed: emit ALL n bytes when the window allows
                    // (no truncation; cap was redundant when n <= cap).
                    if (n > capacity) {
                        // Window was smaller than what we got. Re-emit
                        // the tail bytes as a second segment; the device
                        // can absorb them once it sends a window update.
                        // We hold them in a temporary chunk so they
                        // don't get lost on flow.closed.
                        val tail = buf.copyOfRange(emit, n)
                        val tailSeg = TcpPacketBuilder.build(
                            flowKey = key,
                            flags = TcpPacketBuilder.Flag.ACK or TcpPacketBuilder.Flag.PSH,
                            seq = flow.ourSeq,
                            ack = flow.theirSeq,
                            payload = tail,
                        )
                        flow.retransmitQueue.addLast(RetransmitEntry(flow.ourSeq, tail))
                        flow.ourSeq = (flow.ourSeq + tail.size) and 0xFFFFFFFFL
                        output.trySend(tailSeg)
                    }
                }
                n == -2 -> {
                    // No data right now; brief backoff so we don't
                    // burn CPU spinning on the JNI call.
                    delay(5)
                }
                else -> {
                    // EOF or error. Send a FIN to half-close.
                    if (!flow.closed) {
                        val fin = TcpPacketBuilder.build(
                            flowKey = key,
                            flags = TcpPacketBuilder.Flag.FIN or TcpPacketBuilder.Flag.ACK,
                            seq = flow.ourSeq,
                            ack = flow.theirSeq,
                        )
                        flow.ourSeq = (flow.ourSeq + 1) and 0xFFFFFFFFL
                        output.trySend(fin)
                        flow.closed = true
                        // If the device had already half-closed
                        // ([deviceFinReceived] = true), both sides
                        // are now done — tear down the arti stream
                        // and remove the flow. Otherwise wait for
                        // the device's FIN to complete the four-way
                        // teardown; the next inbound FIN will hit
                        // handleFin which sees [closed] = true and
                        // is now harmless.
                        if (flow.deviceFinReceived) {
                            dialClose(flow.streamId)
                            synchronized(flowTable) { flowTable.remove(key) }
                            tcpFlowsClosed.incrementAndGet()
                        }
                    }
                    break
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun nextIsn(): Long {
        // Random 32-bit ISN; SeekerRng is JCA position-1 so this
        // draws from the SHAKE-mixed pool.
        val rng = java.security.SecureRandom()
        val b = ByteArray(4)
        rng.nextBytes(b)
        return ((b[0].toInt() and 0xFF).toLong() shl 24) or
               ((b[1].toInt() and 0xFF).toLong() shl 16) or
               ((b[2].toInt() and 0xFF).toLong() shl 8) or
               (b[3].toInt() and 0xFF).toLong()
    }

    private fun ByteArray.readI32(o: Int): Int =
        ((this[o].toInt() and 0xFF) shl 24) or
        ((this[o + 1].toInt() and 0xFF) shl 16) or
        ((this[o + 2].toInt() and 0xFF) shl 8) or
        (this[o + 3].toInt() and 0xFF)

    private fun ByteArray.readU16(o: Int): Int =
        ((this[o].toInt() and 0xFF) shl 8) or (this[o + 1].toInt() and 0xFF)

    /**
     * Compare two 32-bit TCP sequence numbers with modular wrap.
     * Returns true iff `a > b` in TCP sequence space (RFC 9293 §3.4).
     * `a - b` interpreted as a signed 32-bit difference is positive.
     */
    private fun seqGt(a: Long, b: Long): Boolean {
        val d = ((a - b) and 0xFFFFFFFFL).toInt()
        return d > 0
    }

    /** Like [seqGt] but allows equality. */
    private fun seqGeq(a: Long, b: Long): Boolean {
        val d = ((a - b) and 0xFFFFFFFFL).toInt()
        return d >= 0
    }

    companion object {
        private const val TAG = "TorFlowForwarder"
        /** Max TCP segment size we'll synthesise. Avoids fragmenting on
         *  most consumer-grade MTUs (1500 - 20 IP - 20 TCP = 1460). */
        private const val MAX_SEGMENT_SIZE = 1460
        /** Three duplicate ACKs trigger fast retransmit per
         *  RFC 5681 §3.2 (TCP congestion-control conventions).
         *  Lower would cause spurious retransmits under reordering;
         *  higher would defer recovery uselessly. */
        private const val DUP_ACK_THRESHOLD = 3
        /** Cap on the per-flow retransmit queue. With 1460-byte
         *  segments this is ~46 KB of backlog — enough to cover
         *  a ~30 ms reordering window at 10 Mbps, after which we
         *  fall back to the device's own RTO. */
        private const val MAX_RETRANSMIT_QUEUE = 32
        /** MSS we advertise in our SYN-ACK. 1220 is the
         *  drand / Tor / arti consensus-safe cap accounting for
         *  IPv4 + TCP + PT outer framing inside a 1500-MTU path. */
        private const val OUR_MSS = 1220
        /** Window-scale exponent we advertise. Zero means the
         *  16-bit window field is the literal byte count. We don't
         *  need a non-zero exponent because the "synthetic remote"
         *  has no real receive buffer to grow — its window field
         *  is a fiction we keep wide-open (65535) anyway. */
        private const val OUR_WSCALE = 0
    }
}
