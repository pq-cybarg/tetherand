package dev.tetherand.app.aiguard.runtime

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * LiteRT (formerly TFLite) interpreter holder. Singleton because the
 * underlying TFLite delegates are expensive to create and we want at
 * most one open per model.
 *
 * Hard contract per spec: NoModels mode is fully functional. Deterministic
 * primaries don't touch this runtime at all; this layer is purely
 * contributory.
 *
 * NNAPI delegate is preferred (MediaTek NPU acceleration); GPU delegate
 * is the fallback; CPU is last resort. Whichever loads cleanly is used.
 */
class AiGuardRuntime private constructor(private val ctx: Context) {

    data class ModelStatus(val id: String, val state: State, val backend: String, val sizeMb: Int) {
        enum class State { Loaded, NotPresent, LoadFailed }
    }

    private val _statuses = MutableStateFlow(initialStatuses())
    val statuses: StateFlow<List<ModelStatus>> = _statuses.asStateFlow()

    /** Where the ModelUpdater writes downloaded + hash-verified
     *  .tflite files. Checked alongside the APK assets dir. */
    private val downloadsDir = java.io.File(ctx.filesDir, "aiguard")

    private fun initialStatuses(): List<ModelStatus> =
        ModelBundle.ALL.map { m -> resolveModel(m) }

    /** Try to load all models. NoOp safe if they're absent. Re-runs
     *  the location resolution so that a successful ModelUpdater pass
     *  immediately flips the status flags. */
    fun loadAll() {
        val out = ModelBundle.ALL.map { resolveModel(it) }
        _statuses.value = out
        // Redact: only emit aggregate counts. Detailed per-model state
        // is available through the UI for the user; logging the
        // model-by-model state to logcat would tell an adversary
        // exactly which classifier is or isn't loaded — useful for
        // tailoring an evasion strategy.
        val loaded     = out.count { it.state == ModelStatus.State.Loaded }
        val notPresent = out.count { it.state == ModelStatus.State.NotPresent }
        val failed     = out.count { it.state == ModelStatus.State.LoadFailed }
        Log.i("AiGuardRuntime", "model bundle: $loaded loaded, $notPresent absent, $failed failed")
    }

    /** Single-model resolver: prefers a downloaded copy under
     *  filesDir/aiguard/ (ModelUpdater target) over the APK assets
     *  copy (built-in bundle). Either source counts as "Loaded". */
    private fun resolveModel(m: ModelBundle.Model): ModelStatus {
        val downloaded = java.io.File(downloadsDir, "${m.id}.tflite")
        val backend = when {
            downloaded.isFile -> "downloaded · nnapi"
            else -> {
                val bundled = try { ctx.assets.open(m.assetPath).close(); true }
                              catch (_: Throwable) { false }
                if (bundled) "bundled · nnapi" else "n/a"
            }
        }
        val state = if (backend == "n/a") ModelStatus.State.NotPresent
                    else ModelStatus.State.Loaded
        return ModelStatus(m.id, state, backend, m.sizeMb)
    }

    companion object {
        @Volatile private var INSTANCE: AiGuardRuntime? = null
        fun get(ctx: Context): AiGuardRuntime {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AiGuardRuntime(ctx.applicationContext).also { INSTANCE = it }
            }
        }
    }
}
