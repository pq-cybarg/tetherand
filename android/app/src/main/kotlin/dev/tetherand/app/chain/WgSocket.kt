package dev.tetherand.app.chain

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Socket

/** Abstract socket carrying WG-UDP frames. Allows obfuscation transports
 *  (UDP-over-TCP, Shadowsocks, QUIC) to replace the raw DatagramSocket. */
interface WgSocket {
    fun send(pkt: ByteArray)
    fun recv(): ByteArray
    fun close()
}

class PlainUdpSocket(private val inner: DatagramSocket) : WgSocket {
    private val buf = ByteArray(2048)
    private val dp = DatagramPacket(buf, buf.size)
    override fun send(pkt: ByteArray) { inner.send(DatagramPacket(pkt, pkt.size)) }
    override fun recv(): ByteArray {
        inner.receive(dp)
        return buf.copyOfRange(0, dp.length)
    }
    override fun close() { try { inner.close() } catch (_: Throwable) {} }
}

/** Length-prefixed framing over TCP — matches Mullvad's udp-over-tcp wire format. */
class UdpOverTcpSocket(private val tcp: Socket) : WgSocket {
    private val out = DataOutputStream(tcp.getOutputStream())
    private val ins = DataInputStream(tcp.getInputStream())
    override fun send(pkt: ByteArray) {
        require(pkt.size in 1..65535) { "WG-UDP frame must fit in u16" }
        out.writeShort(pkt.size)
        out.write(pkt)
        out.flush()
    }
    override fun recv(): ByteArray {
        val len = ins.readUnsignedShort()
        val buf = ByteArray(len)
        ins.readFully(buf)
        return buf
    }
    override fun close() { try { tcp.close() } catch (_: Throwable) {} }
}
