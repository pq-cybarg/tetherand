package dev.tetherand.app.transport

import android.app.Service
import android.content.Intent
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * USB Open Accessory mode receiver.
 *
 * When the Mac shells out to the AOA mode-switch sequence (rusb
 * REQ_GET_PROTOCOL → SEND_STRING × 6 → START), the Seeker re-enumerates
 * with vendor:product 0x18d1:0x2d00 (or 0x2d01 with ADB). At that point
 * the system fires USB_ACCESSORY_ATTACHED with the matching identifier
 * strings; we open the accessory's ParcelFileDescriptor and surface
 * read/write streams to the rest of the app.
 *
 * Service identity must match TETHERAND_AOA_IDENTITY in
 * relay/transport-aoa/src/lib.rs:
 *   manufacturer=Tetherand, model=TetherandRelay, …
 */
class AoaAccessoryService : Service() {

    private var pfd: ParcelFileDescriptor? = null
    private var inStream: FileInputStream? = null
    private var outStream: FileOutputStream? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val acc = intent?.getParcelableExtra<UsbAccessory>(UsbManager.EXTRA_ACCESSORY)
        if (acc == null) {
            Log.w(TAG, "no accessory in intent — stopping")
            stopSelf(); return START_NOT_STICKY
        }
        if (!isTetherandAccessory(acc)) {
            Log.w(TAG, "accessory ${acc.manufacturer}/${acc.model} not Tetherand — stopping")
            stopSelf(); return START_NOT_STICKY
        }
        val usb = getSystemService(UsbManager::class.java)
        val fd = try { usb.openAccessory(acc) }
                 catch (t: Throwable) { Log.w(TAG, "openAccessory: $t"); null }
        if (fd == null) { stopSelf(); return START_NOT_STICKY }
        pfd = fd
        inStream  = FileInputStream(fd.fileDescriptor)
        outStream = FileOutputStream(fd.fileDescriptor)
        Log.i(TAG, "AOA accessory opened")
        return START_STICKY
    }

    override fun onDestroy() {
        try { inStream?.close() } catch (_: Throwable) {}
        try { outStream?.close() } catch (_: Throwable) {}
        try { pfd?.close() } catch (_: Throwable) {}
        inStream = null; outStream = null; pfd = null
        super.onDestroy()
    }

    private fun isTetherandAccessory(a: UsbAccessory): Boolean =
        a.manufacturer == "Tetherand" && a.model == "TetherandRelay"

    companion object { private const val TAG = "AoaAccessory" }
}
