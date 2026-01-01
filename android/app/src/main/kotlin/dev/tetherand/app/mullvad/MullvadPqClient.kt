package dev.tetherand.app.mullvad

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Mullvad's PQ Tunnel-Config-Client. Runs INSIDE an already-established
 * classic WG tunnel — the TCP socket to `10.64.0.1:1337` only routes
 * from inside the WG tunnel, so we MUST be invoked after the WG hop is
 * Connected.
 */
object MullvadPqClient {
    private const val MULLVAD_PQ_HOST = "10.64.0.1"
    private const val MULLVAD_PQ_PORT = 1337
    private const val ALGO_ML_KEM_1024: Byte = 1

    init { System.loadLibrary("tetherand_wg") }

    @JvmStatic external fun nativeKemGenerate(): Long
    @JvmStatic external fun nativeKemPublicKey(handle: Long): ByteArray
    @JvmStatic external fun nativeKemDecapsulate(handle: Long, ciphertext: ByteArray): ByteArray
    @JvmStatic external fun nativeKemFree(handle: Long)

    /**
     * Derive a 32-byte PSK by handshaking with Mullvad's internal config
     * server. Throws on protocol/network/decapsulate error.
     */
    suspend fun deriveSharedSecret(): ByteArray = withContext(Dispatchers.IO) {
        val kem = nativeKemGenerate()
        require(kem != 0L) { "kem allocation failed" }
        try {
            val ek = nativeKemPublicKey(kem)
            require(ek.size == 1568) { "EK size mismatch: ${ek.size}" }

            val sock = Socket()
            sock.connect(InetSocketAddress(MULLVAD_PQ_HOST, MULLVAD_PQ_PORT), 10_000)
            sock.soTimeout = 15_000

            sock.use { s ->
                val out = DataOutputStream(s.getOutputStream())
                val ins = DataInputStream(s.getInputStream())

                out.writeByte(1)                         // version
                out.writeByte(ALGO_ML_KEM_1024.toInt())  // algorithm
                out.writeInt(ek.size)
                out.write(ek)
                out.flush()

                val status = ins.readUnsignedByte()
                if (status != 0) throw RuntimeException("PQ server status=$status")
                val ctLen = ins.readInt()
                require(ctLen in 1..4096) { "PQ ciphertext length out of range: $ctLen" }
                val ct = ByteArray(ctLen)
                ins.readFully(ct)

                val psk = nativeKemDecapsulate(kem, ct)
                require(psk.size == 32) { "decapsulate returned ${psk.size} bytes" }
                psk
            }
        } finally {
            nativeKemFree(kem)
        }
    }
}
