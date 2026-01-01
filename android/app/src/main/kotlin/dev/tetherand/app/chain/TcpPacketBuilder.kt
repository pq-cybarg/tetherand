package dev.tetherand.app.chain

/**
 * IPv4 + TCP packet builder for the [TorFlowForwarder] synthetic-response
 * path. We're the "remote" side of every TCP flow forwarded through Tor;
 * the device sends real packets to us via the TUN, and we synthesise
 * the corresponding return packets here.
 *
 * Reference: RFC 791 (IPv4) + RFC 9293 (TCP). The implementation covers
 * the happy-path subset needed for Tor's TCP-only fabric — SYN-ACK,
 * data segments, FIN-ACK, RST. Edge cases (window scaling, SACK, fast
 * retransmit) deliberately follow upstream Gnirehtet's relay-core TCP
 * stack handling, which the project already vendors via relay/core for
 * the non-Tor path.
 */
object TcpPacketBuilder {

    /**
     * TCP flags packed into a byte (low 6 bits = FIN/SYN/RST/PSH/ACK/URG).
     * The upper 2 bits are zero in standard TCP; spec-defined NS/CWR/ECE
     * flags live in different bits not used here.
     */
    object Flag {
        const val FIN = 0x01
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10
    }

    /**
     * Build a complete IPv4+TCP packet ready to write to the TUN.
     *
     * The semantics are "we are responding from `dstIp:dstPort` to
     * `srcIp:srcPort`" — caller must supply the local-as-seen
     * 4-tuple (source = device, destination = remote we forged), and
     * the builder reverses it for the return-direction packet.
     *
     * @param flowKey Original device-view TcpFlowKey (src = device).
     * @param flags Bitwise OR of [Flag] constants.
     * @param seq Our sequence number (the synthetic-remote-side seq).
     * @param ack Acknowledgement number (next byte we expect from device).
     * @param window Receive window we're advertising (in bytes).
     * @param payload Application data; empty for SYN-ACK / FIN-ACK / RST.
     * @return Bytes suitable for `tunOut.write(...)`.
     */
    fun build(
        flowKey: TorFlowForwarder.TcpFlowKey,
        flags: Int,
        seq: Long,
        ack: Long,
        window: Int = 65535,
        payload: ByteArray = EMPTY_PAYLOAD,
    ): ByteArray {
        val ihl = 20         // IP header length (no options)
        val tcphl = 20       // TCP header length (no options — we don't advertise WSCALE etc.)
        val totalLen = ihl + tcphl + payload.size
        val out = ByteArray(totalLen)

        // ---- IP header ----
        // Version (4) + IHL (5 dwords = 20 bytes)
        out[0] = ((4 shl 4) or (ihl / 4)).toByte()
        // DSCP/ECN
        out[1] = 0
        // Total length
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        // Identification — monotonically increasing across our synthetic packets.
        val id = nextIpId()
        out[4] = ((id ushr 8) and 0xFF).toByte()
        out[5] = (id and 0xFF).toByte()
        // Flags + fragment offset — Don't Fragment, no fragment offset.
        out[6] = 0x40   // DF set
        out[7] = 0
        // TTL — 64 is standard for endpoint-originated packets.
        out[8] = 64.toByte()
        // Protocol — 6 = TCP.
        out[9] = 6.toByte()
        // Header checksum — placeholder zero, computed below.
        out[10] = 0; out[11] = 0
        // Source IP — we forge as the destination of the original flow
        // (i.e. we're answering AS the remote the device tried to reach).
        writeI32(out, 12, flowKey.dstIp)
        // Destination IP — the device.
        writeI32(out, 16, flowKey.srcIp)
        // Compute and write the IP-header checksum.
        val ipChecksum = onesComplementSum(out, 0, ihl)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // ---- TCP header ----
        val tcpOff = ihl
        // Source port (the remote we're impersonating)
        writeU16(out, tcpOff + 0, flowKey.dstPort)
        // Destination port (the device's source)
        writeU16(out, tcpOff + 2, flowKey.srcPort)
        // Sequence number
        writeI32(out, tcpOff + 4, seq.toInt())
        // Acknowledgement number
        writeI32(out, tcpOff + 8, ack.toInt())
        // Data offset (high nibble = tcphl/4) + Reserved (low nibble = 0)
        out[tcpOff + 12] = ((tcphl / 4) shl 4).toByte()
        // Flags
        out[tcpOff + 13] = (flags and 0xFF).toByte()
        // Window
        writeU16(out, tcpOff + 14, window.coerceIn(0, 65535))
        // Checksum placeholder
        out[tcpOff + 16] = 0; out[tcpOff + 17] = 0
        // Urgent pointer
        out[tcpOff + 18] = 0; out[tcpOff + 19] = 0

        // ---- Payload ----
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, out, tcpOff + tcphl, payload.size)
        }

        // ---- TCP checksum ----
        // Per RFC 9293 §3.2: TCP checksum covers the TCP header + payload
        // + a pseudo-header (src/dst IP, zero, proto, TCP length).
        val tcpChecksum = computeTcpChecksum(out, ihl, tcphl + payload.size, flowKey.dstIp, flowKey.srcIp)
        out[tcpOff + 16] = ((tcpChecksum ushr 8) and 0xFF).toByte()
        out[tcpOff + 17] = (tcpChecksum and 0xFF).toByte()

        return out
    }

    // ------------------------------------------------------------------
    // IP-ID counter (monotonic-ish across all flows; 16-bit wrap-around
    // is fine because the IP-ID is just a fragmentation hint and we set DF).
    // ------------------------------------------------------------------

    private var ipIdCounter: Int = (Math.random() * 65536).toInt() and 0xFFFF
    @Synchronized
    private fun nextIpId(): Int {
        ipIdCounter = (ipIdCounter + 1) and 0xFFFF
        return ipIdCounter
    }

    // ------------------------------------------------------------------
    // Checksum routines (RFC 1071 one's-complement)
    // ------------------------------------------------------------------

    /**
     * 16-bit one's-complement sum over `len` bytes starting at `offset`.
     * Returns the FOLDED, COMPLEMENTED result ready to write into a
     * checksum field. This is the standard RFC 1071 internet-checksum.
     */
    private fun onesComplementSum(bytes: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            val word = ((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            // Odd remaining byte gets shifted into the high octet of a virtual zero-padded word.
            sum += (bytes[i].toInt() and 0xFF) shl 8
        }
        // Fold any carries into 16 bits.
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv().toInt()) and 0xFFFF
    }

    /**
     * TCP checksum per RFC 9293 §3.2. The pseudo-header is:
     *   [src_ip(4) | dst_ip(4) | zero(1) | proto(1) | tcp_length(2)]
     * which we build into a small scratch buffer for the sum, then
     * combine with the TCP-header-plus-payload sum.
     */
    private fun computeTcpChecksum(
        pkt: ByteArray, tcpOffset: Int, tcpLen: Int,
        srcIp: Int, dstIp: Int,
    ): Int {
        val pseudo = ByteArray(12)
        writeI32(pseudo, 0, srcIp)
        writeI32(pseudo, 4, dstIp)
        pseudo[8] = 0
        pseudo[9] = 6   // TCP protocol number
        pseudo[10] = ((tcpLen ushr 8) and 0xFF).toByte()
        pseudo[11] = (tcpLen and 0xFF).toByte()

        // Manual two-pass sum so we don't allocate a combined buffer.
        var sum = 0L
        for (i in 0 until pseudo.size step 2) {
            sum += ((pseudo[i].toInt() and 0xFF) shl 8) or (pseudo[i + 1].toInt() and 0xFF)
        }
        var i = tcpOffset
        val end = tcpOffset + tcpLen
        while (i + 1 < end) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (pkt[i].toInt() and 0xFF) shl 8
        }
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv().toInt()) and 0xFFFF
    }

    // ------------------------------------------------------------------
    // Big-endian writers
    // ------------------------------------------------------------------

    private fun writeI32(b: ByteArray, o: Int, v: Int) {
        b[o]     = ((v ushr 24) and 0xFF).toByte()
        b[o + 1] = ((v ushr 16) and 0xFF).toByte()
        b[o + 2] = ((v ushr 8) and 0xFF).toByte()
        b[o + 3] = (v and 0xFF).toByte()
    }

    private fun writeU16(b: ByteArray, o: Int, v: Int) {
        b[o]     = ((v ushr 8) and 0xFF).toByte()
        b[o + 1] = (v and 0xFF).toByte()
    }

    private val EMPTY_PAYLOAD = ByteArray(0)
}
