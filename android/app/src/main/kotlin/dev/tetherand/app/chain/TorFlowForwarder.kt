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
 * **Happy-path scope (v0.1).** The implementation handles SYN-ACK,
 * forward-direction data delivery, reverse-direction injection, and
 * FIN-ACK / RST teardown. Window scaling, SACK, fast-retransmit, and
 * out-of-order delivery edge cases are deferred to follow-on patches
 * that mirror the relay-core/Gnirehtet handling for those cases —
 * the same machinery is already vendored under `relay/core` for the
 * non-Tor relay path, and porting it here is a refactor rather than
 * a re-invention.
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
     */
    class TcpFlow(
        val streamId: Long,
        val openedAtMs: Long,
        @Volatile var ourSeq: Long,         // next byte we'll send (synthetic)
        @Volatile var theirSeq: Long,       // next byte from device we expect to ack
        var pumpJob: Job? = null,
        @Volatile var closed: Boolean = false,
    )

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
        val syn = (flags and TcpPacketBuilder.Flag.SYN) != 0
        val fin = (flags and TcpPacketBuilder.Flag.FIN) != 0
        val rst = (flags and TcpPacketBuilder.Flag.RST) != 0
        val ack = (flags and TcpPacketBuilder.Flag.ACK) != 0
        val payloadOff = ihl + tcphlBytes
        val payloadLen = pkt.size - payloadOff
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
                    // Brand-new SYN. Dial through Tor, synthesize SYN-ACK.
                    handleNewSyn(key, theirSeq, output)
                }
                existing != null && payloadLen > 0 -> {
                    // In-flow data segment. Forward to arti + ack the bytes.
                    handleData(key, existing, pkt, payloadOff, payloadLen, output)
                }
                existing != null && fin -> {
                    // Device half-close — flush + close stream.
                    handleFin(key, existing, output)
                }
                existing != null && ack && !syn && payloadLen == 0 -> {
                    // Plain ACK with no data — keepalive / window update. Ignore.
                }
                else -> {
                    // Anything else: state mismatch. Send RST.
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
     * an initial sequence number, synthesize SYN-ACK, and spawn the
     * Arti-→-device pump coroutine.
     */
    private fun handleNewSyn(key: TcpFlowKey, theirSeq: Long, output: Channel<ByteArray>) {
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
        val flow = TcpFlow(
            streamId = streamId,
            openedAtMs = System.currentTimeMillis(),
            ourSeq = ourIsn,
            theirSeq = (theirSeq + 1) and 0xFFFFFFFFL,   // ack the SYN
        )
        flowTable[key] = flow
        tcpFlowsOpened.incrementAndGet()

        // Synthesize SYN-ACK back to the device.
        val synAck = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.SYN or TcpPacketBuilder.Flag.ACK,
            seq = ourIsn,
            ack = flow.theirSeq,
        )
        flow.ourSeq = (ourIsn + 1) and 0xFFFFFFFFL    // SYN consumes 1 seq
        scope.launch { output.trySend(synAck) }

        // Spawn the reverse-direction pump: read from Arti stream,
        // wrap chunks in synthetic TCP segments, push to TUN.
        flow.pumpJob = scope.launch { pumpStreamToDevice(key, flow, output) }
    }

    /**
     * Device sent us a TCP segment with payload. Forward the payload
     * to the Arti stream, then ack the bytes back to the device.
     */
    private fun handleData(
        key: TcpFlowKey, flow: TcpFlow,
        pkt: ByteArray, payloadOff: Int, payloadLen: Int,
        output: Channel<ByteArray>,
    ) {
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
     * Device half-closed (sent FIN). Flush pending data to Arti, then
     * close the stream + send FIN-ACK back.
     */
    private fun handleFin(key: TcpFlowKey, flow: TcpFlow, output: Channel<ByteArray>) {
        flow.theirSeq = (flow.theirSeq + 1) and 0xFFFFFFFFL    // FIN consumes 1 seq
        dialClose(flow.streamId)
        flow.closed = true
        flow.pumpJob?.cancel()
        val finAck = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.FIN or TcpPacketBuilder.Flag.ACK,
            seq = flow.ourSeq,
            ack = flow.theirSeq,
        )
        flow.ourSeq = (flow.ourSeq + 1) and 0xFFFFFFFFL    // our FIN also consumes 1 seq
        scope.launch { output.trySend(finAck) }
        flowTable.remove(key)
        tcpFlowsClosed.incrementAndGet()
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
     * to the TUN output channel.
     */
    private suspend fun pumpStreamToDevice(
        key: TcpFlowKey, flow: TcpFlow, output: Channel<ByteArray>,
    ) {
        val buf = ByteArray(MAX_SEGMENT_SIZE)
        while (!flow.closed) {
            val n = try { streamRead(flow.streamId, buf) } catch (_: Throwable) { -1 }
            when {
                n > 0 -> {
                    val chunk = buf.copyOfRange(0, n)
                    val seg = TcpPacketBuilder.build(
                        flowKey = key,
                        flags = TcpPacketBuilder.Flag.ACK or TcpPacketBuilder.Flag.PSH,
                        seq = flow.ourSeq,
                        ack = flow.theirSeq,
                        payload = chunk,
                    )
                    flow.ourSeq = (flow.ourSeq + n) and 0xFFFFFFFFL
                    output.trySend(seg)
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

    companion object {
        private const val TAG = "TorFlowForwarder"
        /** Max TCP segment size we'll synthesise. Avoids fragmenting on
         *  most consumer-grade MTUs (1500 - 20 IP - 20 TCP = 1460). */
        private const val MAX_SEGMENT_SIZE = 1460
    }
}
