package dev.tetherand.app.threat.root

import java.io.DataInputStream
import java.io.InputStream

/**
 * Parser for the MediaTek modem binary log format ("mdlog").
 *
 * Frame layout (after reverse-engineering by AOSP MTK builds and
 * crocodile-hunter reference):
 *   [magic(4)='MDLG' | version(1) | type(1) | length(2) | tsMs(8) | payload(length)]
 *   All multi-byte fields little-endian.
 *
 * Common record types:
 *   0x01  LTE RRC Connection Request
 *   0x02  LTE RRC Connection Setup
 *   0x10  TAU / Tracking Area Update
 *   0x20  Paging
 *   0x30  IRAT reselection (LTE → UMTS / GSM downgrade)
 *
 * Each record is yielded as a `Record` data class; consumers correlate
 * with the M7a heuristics (RAT-downgrade, paging-storm, TAC-change).
 */
object MdlogParser {

    data class Record(val type: Int, val tsMs: Long, val payload: ByteArray)

    private const val MAGIC: Int = 0x474C444D  // 'MDLG' little-endian

    fun parse(stream: InputStream): Sequence<Record> = sequence {
        val dis = DataInputStream(stream)
        try {
            while (true) {
                val magic = readU32Le(dis)
                if (magic != MAGIC) {
                    // Resync: read forward until we find the next magic.
                    if (!resync(dis)) return@sequence
                }
                val _version = dis.readUnsignedByte()
                val type = dis.readUnsignedByte()
                val length = readU16Le(dis)
                val tsMs = readU64Le(dis)
                val payload = ByteArray(length)
                dis.readFully(payload)
                yield(Record(type, tsMs, payload))
            }
        } catch (_: Throwable) { /* EOF / corrupt — terminate */ }
    }

    private fun resync(dis: DataInputStream): Boolean {
        // Slide a 4-byte window forward looking for MAGIC.
        var w = 0
        while (true) {
            val b = try { dis.read() } catch (_: Throwable) { return false }
            if (b == -1) return false
            w = (w ushr 8) or (b shl 24)
            if (w == MAGIC) return true
        }
    }

    private fun readU16Le(dis: DataInputStream): Int {
        val a = dis.readUnsignedByte(); val b = dis.readUnsignedByte()
        return (a or (b shl 8))
    }
    private fun readU32Le(dis: DataInputStream): Int {
        val a = dis.readUnsignedByte(); val b = dis.readUnsignedByte()
        val c = dis.readUnsignedByte(); val d = dis.readUnsignedByte()
        return a or (b shl 8) or (c shl 16) or (d shl 24)
    }
    private fun readU64Le(dis: DataInputStream): Long {
        var v = 0L
        for (i in 0..7) v = v or (dis.readUnsignedByte().toLong() shl (i * 8))
        return v
    }
}
