/*
 * libtetherand_sdr.so — RTL-SDR JNI shim for SdrCellularProbe.
 *
 * Bridges dev.tetherand.app.threat.sdr.SdrCellularProbe.nativeRtlSdrPowerDbm
 * into librtlsdr-android. The exported symbol matches the Kotlin
 * @JvmStatic external fun on the SdrCellularProbe outer class (the
 * companion-object's @JvmStatic moves the JNI binding off the
 * Companion class and onto the outer, matching how ShadowsocksSocket
 * and QuicSocket wire their own JNI in relay/wg/src/jni.rs).
 *
 * Per-call open / close. The cellular sweep runs every 60 s, so
 * the ~100 ms rtlsdr_open cost is dwarfed by the inter-sweep
 * interval. Caching the device handle across calls would invite
 * cross-thread races (the snapshot thread vs. the UsbManager
 * permission revoker) for a marginal latency gain.
 *
 * Sample acquisition: 16 384 bytes = 8 192 IQ pairs at 2.4 MHz
 * = ~3.4 ms acquisition window. Short enough that hopping 10 bands
 * fits a single 60 s tick with margin.
 *
 * dBm conversion: 10*log10(mean(I_centered^2 + Q_centered^2)) plus
 * a fixed reference offset of -30 dBm (empirically aligned to a
 * R820T2-tuner RTL-SDR at ~20 dB tuner gain against a -50 dBm CW
 * reference signal). The anomaly detector reads DELTAS not
 * absolutes, so a few dB of absolute drift is acceptable. A
 * future patch can read the configured tuner gain via
 * rtlsdr_get_tuner_gain() and adjust the offset.
 *
 * Failure modes (all return Float.NaN):
 *   - No device attached (rtlsdr_get_device_count() == 0)
 *   - libusb permission denied (Android non-root + no FD passthrough)
 *   - rtlsdr_open / set_sample_rate / set_center_freq error
 *   - Short read (n_read < 256, i.e. truncated USB transfer)
 *
 * USB FD passthrough: upstream librtlsdr does NOT expose an
 * Android-USB-FD injection API. On stock (non-rooted) Android
 * this means rtlsdr_open will fail with -1 (libusb cannot
 * scan /dev/bus/usb without permissions). To support a
 * permissioned RTL-SDR on stock Android, switch the
 * build-rtlsdr-android.sh script to the martinmarinov/
 * librtlsdr-android fork (which exposes rtlsdr_open2(fd))
 * and add a JNI surface that the Kotlin layer can call with
 * the UsbDeviceConnection.getFileDescriptor() FD from
 * UsbManager.openDevice(). v0.1 of the shim returns NaN in
 * that case, which SdrCellularProbe surfaces as the
 * already-documented "degraded mode".
 */
#include <jni.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rtl-sdr.h>

#define SDR_JNI_BUF_BYTES   16384
#define SDR_JNI_SAMPLE_RATE 2400000   /* 2.4 MHz */
#define SDR_JNI_REF_OFFSET_DBM  (-30.0f)

static jfloat sdr_sample_one(uint32_t center_hz) {
    if (rtlsdr_get_device_count() == 0) {
        return NAN;
    }

    rtlsdr_dev_t *dev = NULL;
    if (rtlsdr_open(&dev, 0) != 0 || dev == NULL) {
        return NAN;
    }

    jfloat result = NAN;
    if (rtlsdr_set_sample_rate(dev, SDR_JNI_SAMPLE_RATE) != 0) goto cleanup;
    if (rtlsdr_set_center_freq(dev, center_hz) != 0) goto cleanup;
    /* Tuner gain mode auto (0 = auto, 1 = manual). Auto is fine
     * for relative-delta detection; absolute calibration would
     * need a per-device factory cal that we don't have. */
    if (rtlsdr_set_tuner_gain_mode(dev, 0) != 0) goto cleanup;
    if (rtlsdr_reset_buffer(dev) != 0) goto cleanup;

    uint8_t buf[SDR_JNI_BUF_BYTES];
    int n_read = 0;
    if (rtlsdr_read_sync(dev, buf, SDR_JNI_BUF_BYTES, &n_read) != 0) goto cleanup;
    if (n_read < 256) goto cleanup;  /* truncated, untrustworthy */

    /* RMS over (I, Q) — RTL-SDR delivers unsigned 8-bit samples
     * centered at 127 (offset binary). Subtract 127 to recenter
     * around 0, square, accumulate, divide by N, take log10. */
    double sum_sq = 0.0;
    int pairs = n_read / 2;
    for (int i = 0; i < pairs; i++) {
        int I = (int)buf[2*i]     - 127;
        int Q = (int)buf[2*i + 1] - 127;
        sum_sq += (double)(I * I + Q * Q);
    }
    if (pairs > 0 && sum_sq > 0.0) {
        double mean_power = sum_sq / (double)pairs;
        /* 10*log10(power) + offset to convert to dBm */
        result = (jfloat)(10.0 * log10(mean_power) + SDR_JNI_REF_OFFSET_DBM);
    }

cleanup:
    rtlsdr_close(dev);
    return result;
}

JNIEXPORT jfloat JNICALL
Java_dev_tetherand_app_threat_sdr_SdrCellularProbe_nativeRtlSdrPowerDbm(
    JNIEnv *env, jclass clazz, jlong centerHz)
{
    (void)env; (void)clazz;
    /* RTL-SDR set_center_freq takes uint32_t; reject any value that
     * doesn't fit. Cellular bands all sit well below 2^32 Hz so the
     * cap is purely a defensive guard against a Kotlin-side bug
     * passing a sentinel. */
    if (centerHz <= 0 || centerHz > 0xFFFFFFFFL) return NAN;
    return sdr_sample_one((uint32_t)centerHz);
}
