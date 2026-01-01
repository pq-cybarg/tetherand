package dev.tetherand.app.chain

import android.content.Context
import java.io.File

/**
 * Stages PT binaries from the APK's nativeLibraryDir into the app's
 * cacheDir/pts/ so they're executable. Android packs binaries shipped
 * in `jniLibs/arm64-v8a/` as `libxxx.so`; we rename them to extension-
 * less files (the names arti will spawn) and chmod +x.
 *
 * Binary names expected in jniLibs/arm64-v8a/:
 *   - libtetherand_pt.so    → tetherand-pt        (obfs4 / meek / webtunnel)
 *   - libsnowflake_client.so → snowflake-client   (Go upstream)
 *   - libconjure_client.so   → conjure-client     (Go upstream)
 *
 * Missing binaries return null — the corresponding PT then errors at
 * TorBuilder.build() with the M6.x message pointing the user at the
 * build script.
 */
object PtBinaryStager {

    data class Staged(val ptBridge: String?, val snowflake: String?, val conjure: String?)

    private const val BIN_PT       = "tetherand-pt"
    private const val BIN_SNOWFLAKE = "snowflake-client"
    private const val BIN_CONJURE   = "conjure-client"

    private const val LIB_PT       = "libtetherand_pt.so"
    private const val LIB_SNOWFLAKE = "libsnowflake_client.so"
    private const val LIB_CONJURE   = "libconjure_client.so"

    fun stage(ctx: Context): Staged {
        val nativeDir = File(ctx.applicationInfo.nativeLibraryDir)
        val ptsDir = File(ctx.cacheDir, "pts").also { it.mkdirs() }
        return Staged(
            ptBridge = stageOne(nativeDir, ptsDir, LIB_PT, BIN_PT),
            snowflake = stageOne(nativeDir, ptsDir, LIB_SNOWFLAKE, BIN_SNOWFLAKE),
            conjure = stageOne(nativeDir, ptsDir, LIB_CONJURE, BIN_CONJURE),
        )
    }

    private fun stageOne(nativeDir: File, outDir: File, srcName: String, dstName: String): String? {
        val src = File(nativeDir, srcName)
        if (!src.exists()) return null
        val dst = File(outDir, dstName)
        // Copy + chmod every time so re-installs of the APK refresh the
        // binary. Symlinking would be cleaner but Android often disallows
        // setting symlinks in cacheDir.
        src.inputStream().use { input ->
            dst.outputStream().use { input.copyTo(it) }
        }
        dst.setExecutable(true, false)
        return dst.absolutePath
    }
}
