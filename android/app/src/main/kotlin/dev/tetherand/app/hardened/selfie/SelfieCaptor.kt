package dev.tetherand.app.hardened.selfie

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import androidx.core.content.ContextCompat
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * One-shot front-camera still capture.
 *
 * Surface-less Camera2 capture: we never attach a Surface to the
 * screen, so the user does not see a preview. The capture runs on
 * a dedicated HandlerThread, the ImageReader writes a single JPEG,
 * and we tear down the session immediately afterward.
 *
 * Returns the raw JPEG bytes on success or null on any failure
 * (permission denied, no front camera, hardware busy, etc).
 */
object SelfieCaptor {

    /** JPEG resolution. 640×480 is the smallest most front cameras
     *  expose and is plenty for face-grade evidence; keeps storage
     *  modest if the attempt counter ticks fast. */
    private const val WIDTH = 640
    private const val HEIGHT = 480

    suspend fun captureFront(ctx: Context): ByteArray? {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) return null

        val mgr = ctx.getSystemService(Context.CAMERA_SERVICE) as? CameraManager ?: return null
        val frontId = mgr.cameraIdList.firstOrNull { id ->
            mgr.getCameraCharacteristics(id)
                .get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT
        } ?: return null

        val thread = HandlerThread("selfie-capture").apply { start() }
        val handler = Handler(thread.looper)
        val reader = ImageReader.newInstance(WIDTH, HEIGHT, ImageFormat.JPEG, 1)

        return try {
            val bytes = suspendCancellableCoroutine<ByteArray?> { cont ->
                reader.setOnImageAvailableListener({ r ->
                    val image = r.acquireNextImage() ?: run {
                        if (cont.isActive) cont.resume(null)
                        return@setOnImageAvailableListener
                    }
                    try {
                        val buf = image.planes[0].buffer
                        val data = ByteArray(buf.remaining())
                        buf.get(data)
                        if (cont.isActive) cont.resume(data)
                    } finally {
                        image.close()
                    }
                }, handler)

                try {
                    mgr.openCamera(frontId, object : CameraDevice.StateCallback() {
                        override fun onOpened(device: CameraDevice) {
                            try {
                                device.createCaptureSession(
                                    listOf(reader.surface),
                                    object : CameraCaptureSession.StateCallback() {
                                        override fun onConfigured(session: CameraCaptureSession) {
                                            val req = device.createCaptureRequest(
                                                CameraDevice.TEMPLATE_STILL_CAPTURE
                                            ).apply {
                                                addTarget(reader.surface)
                                                set(CaptureRequest.CONTROL_AF_MODE,
                                                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                                            }.build()
                                            session.capture(req, null, handler)
                                        }
                                        override fun onConfigureFailed(session: CameraCaptureSession) {
                                            if (cont.isActive) cont.resume(null)
                                        }
                                    },
                                    handler,
                                )
                            } catch (t: Throwable) {
                                if (cont.isActive) cont.resumeWithException(t)
                            }
                        }
                        override fun onDisconnected(device: CameraDevice) {
                            device.close()
                            if (cont.isActive) cont.resume(null)
                        }
                        override fun onError(device: CameraDevice, error: Int) {
                            device.close()
                            if (cont.isActive) cont.resume(null)
                        }
                    }, handler)
                } catch (t: SecurityException) {
                    if (cont.isActive) cont.resumeWithException(t)
                } catch (t: Throwable) {
                    if (cont.isActive) cont.resumeWithException(t)
                }
            }
            bytes
        } catch (_: Throwable) {
            null
        } finally {
            reader.close()
            thread.quitSafely()
        }
    }
}
