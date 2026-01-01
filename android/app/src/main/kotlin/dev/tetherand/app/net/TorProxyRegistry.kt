package dev.tetherand.app.net

import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-wide registry for the embedded Arti SOCKS5 listener port.
 *
 * The pattern: anything in the app that successfully bootstraps an
 * Arti runtime + SOCKS5 listener (today: `TorHop.start()`) publishes
 * its `127.0.0.1:<port>` here. Anything that wants to route outbound
 * traffic through Tor — most notably `PublicBeacons` fetching from
 * NIST + drand — reads it.
 *
 * `null` means **no Tor is up right now**. Consumers MUST NOT fall
 * back to clear-net in that case. The privacy intent is: if Tor
 * isn't available, defer the action rather than leak the device IP.
 *
 * One slot only — if multiple TorHop instances exist (e.g. user runs
 * a chain AND has Hardened-Mode-only beacon-tor going), the most
 * recently registered one wins. That's intentional: beacons traffic
 * is low-volume; piggybacking on whatever Tor is already up is
 * cheaper than running a second one.
 */
object TorProxyRegistry {
    private val current = AtomicReference<Proxy?>(null)
    private val bridgeRotation = AtomicReference<dev.tetherand.app.chain.BridgeRotation?>(null)

    /** Publish the current Arti SOCKS5 port. Call with `null` on Tor shutdown. */
    fun publish(socksPort: Int?) {
        current.set(socksPort?.let {
            Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", it))
        })
    }

    /** Current Tor SOCKS5 proxy, or `null` if no Tor is running. */
    fun currentProxy(): Proxy? = current.get()

    /** Publish the active [BridgeRotation] reference so UI cards can
     *  surface it (and trigger `rotateNow()`) without holding their
     *  own TorHop reference. Call with `null` on Tor shutdown. */
    fun publishBridgeRotation(rot: dev.tetherand.app.chain.BridgeRotation?) {
        bridgeRotation.set(rot)
    }

    /** Current bridge-rotation worker, or `null` if no Tor is running
     *  OR the configured bridge set has fewer than 2 entries. */
    fun currentBridgeRotation(): dev.tetherand.app.chain.BridgeRotation? = bridgeRotation.get()
}
