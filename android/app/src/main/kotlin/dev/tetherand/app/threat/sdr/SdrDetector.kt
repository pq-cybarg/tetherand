package dev.tetherand.app.threat.sdr

import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

/**
 * Detect plugged-in SDR dongles via USB-OTG.
 *
 * Supported devices (vendor:product):
 *   - RTL-SDR (Realtek RTL2832U based):
 *       0x0bda:0x2832  RTL2832U
 *       0x0bda:0x2838  RTL2838U
 *       0x0bda:0x2832  Generic RTL clones
 *   - HackRF One:
 *       0x1d50:0x6089
 *   - bladeRF:
 *       0x2cf0:0x5246
 *   - LimeSDR:
 *       0x1d50:0x6108  LimeSDR-USB
 *       0x1d50:0x6120  LimeSDR-Mini
 *
 * Surfaces are populated for the UI; the actual LTE control-channel
 * decoder lives in the M7b.x librtlsdr-android + libsrsRAN integration.
 */
object SdrDetector {

    data class SdrDevice(val name: String, val vendorId: Int, val productId: Int, val capable: SdrCapable)
    enum class SdrCapable { RtlSdr, HackRf, BladeRf, LimeSdr }

    private data class Known(val vid: Int, val pid: Int, val name: String, val cap: SdrCapable)
    private val KNOWN: List<Known> = listOf(
        Known(0x0bda, 0x2832, "RTL-SDR (RTL2832U)",        SdrCapable.RtlSdr),
        Known(0x0bda, 0x2838, "RTL-SDR (RTL2838U)",        SdrCapable.RtlSdr),
        Known(0x1d50, 0x6089, "HackRF One",                SdrCapable.HackRf),
        Known(0x2cf0, 0x5246, "Nuand bladeRF",             SdrCapable.BladeRf),
        Known(0x1d50, 0x6108, "Lime Microsystems LimeSDR", SdrCapable.LimeSdr),
        Known(0x1d50, 0x6120, "Lime Microsystems LimeSDR-Mini", SdrCapable.LimeSdr),
    )

    fun scan(ctx: Context): List<SdrDevice> {
        val mgr = ctx.getSystemService(Context.USB_SERVICE) as UsbManager
        val out = mutableListOf<SdrDevice>()
        for ((_, dev: UsbDevice) in mgr.deviceList) {
            val match = KNOWN.firstOrNull { it.vid == dev.vendorId && it.pid == dev.productId }
                ?: continue
            out.add(SdrDevice(match.name, dev.vendorId, dev.productId, match.cap))
        }
        return out
    }

    /** Empty list means the user can run RTL-SDR for ~$30, HackRF for ~$300. */
    fun isSdrAvailable(ctx: Context): Boolean = scan(ctx).isNotEmpty()
}
