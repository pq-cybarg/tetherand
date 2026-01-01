package dev.tetherand.app.threat.collector

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import cz.mroczis.netmonster.core.factory.NetMonsterFactory
import cz.mroczis.netmonster.core.model.cell.CellGsm
import cz.mroczis.netmonster.core.model.cell.CellLte
import cz.mroczis.netmonster.core.model.cell.CellNr
import cz.mroczis.netmonster.core.model.cell.CellWcdma
import cz.mroczis.netmonster.core.model.cell.ICell
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class CellObservation(
    val rat: String,                  // "LTE", "NR", "GSM", "UMTS"
    val mccMnc: String,
    val lac: Int,                     // LAC or TAC
    val tac: Int? = null,
    val cid: Long,
    val pci: Int? = null,
    val earfcn: Int? = null,
    val signalDbm: Int? = null,
    val neighborCount: Int = 0,
    val tsMs: Long = System.currentTimeMillis(),
)

/** Snapshots the cell environment via NetMonster-core on demand. */
class CellInfoSource(private val ctx: Context) {
    private val nm = NetMonsterFactory.get(ctx)
    private val _observations = MutableStateFlow<List<CellObservation>>(emptyList())
    val observations: StateFlow<List<CellObservation>> = _observations.asStateFlow()

    fun sample() {
        // Emulator path: NetMonster returns an empty list because there's
        // no real modem. Inject synthetic cell observations so the
        // BTS / RAT / TAC / EARFCN / reattach heuristics still run.
        if (HardwareMocks.shouldMockCellular()) {
            _observations.value = HardwareMocks.syntheticCells()
            return
        }
        if (!hasPermission()) return
        val cells: List<ICell> = try { nm.getCells() } catch (_: Throwable) { emptyList() }
        val out = cells.mapNotNull { translate(it) }
        if (out.isNotEmpty()) _observations.value = out
    }

    private fun translate(cell: ICell): CellObservation? = when (cell) {
        is CellLte -> {
            val mcc = cell.network?.mcc ?: return null
            val mnc = cell.network?.mnc ?: return null
            CellObservation(
                rat = "LTE",
                mccMnc = "$mcc$mnc",
                lac = cell.tac ?: 0,
                tac = cell.tac,
                cid = (cell.eci?.toLong() ?: cell.cid?.toLong() ?: 0L),
                pci = cell.pci,
                earfcn = cell.band?.downlinkEarfcn,
                signalDbm = cell.signal.rsrp?.toInt(),
            )
        }
        is CellNr -> {
            val mcc = cell.network?.mcc ?: return null
            val mnc = cell.network?.mnc ?: return null
            CellObservation(
                rat = "NR",
                mccMnc = "$mcc$mnc",
                lac = cell.tac ?: 0,
                tac = cell.tac,
                cid = cell.nci ?: 0L,
                pci = cell.pci,
                earfcn = cell.band?.downlinkArfcn,
                signalDbm = cell.signal.ssRsrp?.toInt(),
            )
        }
        is CellGsm -> {
            val mcc = cell.network?.mcc ?: return null
            val mnc = cell.network?.mnc ?: return null
            CellObservation(
                rat = "GSM",
                mccMnc = "$mcc$mnc",
                lac = cell.lac ?: 0,
                cid = (cell.cid?.toLong() ?: 0L),
                signalDbm = cell.signal.rssi?.toInt(),
            )
        }
        is CellWcdma -> {
            val mcc = cell.network?.mcc ?: return null
            val mnc = cell.network?.mnc ?: return null
            CellObservation(
                rat = "UMTS",
                mccMnc = "$mcc$mnc",
                lac = cell.lac ?: 0,
                cid = (cell.ci?.toLong() ?: 0L),
                signalDbm = cell.signal.rssi?.toInt(),
            )
        }
        else -> null
    }

    private fun hasPermission(): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
}
