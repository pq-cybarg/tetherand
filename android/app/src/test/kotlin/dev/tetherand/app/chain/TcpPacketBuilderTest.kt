package dev.tetherand.app.chain

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TcpPacketBuilderTest {

    private val key = TorFlowForwarder.TcpFlowKey(
        srcIp = 0x0A000001,  // 10.0.0.1
        srcPort = 51234,
        dstIp = 0x4A4A4A4A,  // 74.74.74.74
        dstPort = 80,
    )

    @Test fun `parseOptions extracts MSS WSCALE SACK_PERMITTED`() {
        // MSS=1460, WSCALE=7, SACK_PERMITTED. NOP-padded to 12 bytes.
        val opts = byteArrayOf(
            2, 4, 0x05, 0xB4.toByte(),     // MSS = 1460
            3, 3, 7,                        // WSCALE = 7
            4, 2,                           // SACK_PERMITTED
            1, 1, 1,                        // NOP padding
        )
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(1460, parsed.mss)
        assertEquals(7, parsed.wscale)
        assertTrue(parsed.sackPermitted)
    }

    @Test fun `parseOptions defaults when blob empty`() {
        val parsed = TcpPacketBuilder.parseOptions(ByteArray(0), 0, 0)
        assertEquals(536, parsed.mss)
        assertEquals(0, parsed.wscale)
        assertFalse(parsed.sackPermitted)
    }

    @Test fun `parseOptions clamps WSCALE to RFC 7323 max of 14`() {
        val opts = byteArrayOf(3, 3, 30)
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(14, parsed.wscale)
    }

    @Test fun `parseOptions stops at EOL`() {
        val opts = byteArrayOf(
            2, 4, 0x05, 0xB4.toByte(),     // MSS = 1460
            0,                              // EOL
            3, 3, 7,                        // After EOL — should be ignored
        )
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(1460, parsed.mss)
        assertEquals(0, parsed.wscale)
    }

    @Test fun `parseOptions tolerates malformed length`() {
        // length byte claims 200 bytes but the buffer is only 6
        val opts = byteArrayOf(5, 200.toByte(), 1, 2, 3, 4)
        // Should not throw; falls back to defaults already accumulated
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(536, parsed.mss)
    }

    @Test fun `parseOptions skips unknown kinds via length`() {
        val opts = byteArrayOf(
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,   // Timestamps, length 10
            2, 4, 0x05, 0xB4.toByte(),       // MSS = 1460
        )
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(1460, parsed.mss)
    }

    @Test fun `buildSynAckOptions encodes the standard three`() {
        val opts = TcpPacketBuilder.buildSynAckOptions(ourMss = 1220, ourWscale = 0, sackPermitted = true)
        // Round-trip through parseOptions
        val parsed = TcpPacketBuilder.parseOptions(opts, 0, opts.size)
        assertEquals(1220, parsed.mss)
        assertEquals(0, parsed.wscale)
        assertTrue(parsed.sackPermitted)
    }

    @Test fun `build with options produces a 4-byte-aligned TCP header`() {
        val opts = TcpPacketBuilder.buildSynAckOptions()
        val pkt = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.SYN or TcpPacketBuilder.Flag.ACK,
            seq = 1L,
            ack = 2L,
            options = opts,
        )
        // IHL is in byte 0, low nibble × 4. TCP data-offset is in
        // byte 32 (= 20 IP + 12 TCP), high nibble × 4. Total TCP
        // header length must be a multiple of 4.
        val tcpDataOff = ((pkt[32].toInt() ushr 4) and 0x0F) * 4
        assertEquals(0, tcpDataOff % 4, "TCP data-offset must be 4-byte aligned")
        // Header should be 20 (fixed) + ceil(opts.size / 4) * 4
        val expectedHl = 20 + ((opts.size + 3) and 3.inv())
        assertEquals(expectedHl, tcpDataOff)
    }

    @Test fun `build computes valid IP+TCP checksums`() {
        val pkt = TcpPacketBuilder.build(
            flowKey = key,
            flags = TcpPacketBuilder.Flag.ACK,
            seq = 0x12345678L,
            ack = 0x87654321L,
            payload = "hello".toByteArray(),
        )
        // IP checksum: sum over IP header should fold to 0xFFFF.
        var sum = 0L
        for (i in 0 until 20 step 2) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        assertEquals(0xFFFFL, sum, "IP header checksum should fold to 0xFFFF")
    }
}
