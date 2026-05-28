package dev.tetherand.app.mullvad

import android.content.Context

object DaitaMachines {
    private const val DIR = "daita-machines"

    /** Read all bundled .mb machine files, return their raw bytes. */
    fun load(ctx: Context): List<ByteArray> {
        val asset = ctx.assets
        val names = try { asset.list(DIR).orEmpty() } catch (_: Throwable) { emptyArray() }
        return names
            .filter { it.endsWith(".mb") }
            .map { name -> asset.open("$DIR/$name").use { it.readBytes() } }
    }
}
