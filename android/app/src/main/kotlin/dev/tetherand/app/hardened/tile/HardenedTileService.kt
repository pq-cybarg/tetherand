package dev.tetherand.app.hardened.tile

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.tetherand.app.hardened.HardenedModeManager

class HardenedTileService : TileService() {
    private lateinit var manager: HardenedModeManager

    override fun onCreate() {
        super.onCreate()
        manager = HardenedModeManager(applicationContext)
    }

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        if (manager.active.value) manager.exit() else manager.enter()
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        if (manager.active.value) {
            tile.state = Tile.STATE_ACTIVE
            tile.label = "5364C13D Mode"
            tile.contentDescription = "Hardened Mode is ON"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.label = "5364C13D Mode"
            tile.contentDescription = "Hardened Mode is OFF"
        }
        tile.updateTile()
    }
}
