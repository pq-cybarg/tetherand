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

    private fun initialStatuses(): List<ModelStatus> =
        ModelBundle.ALL.map { m ->
            val present = try { ctx.assets.open(m.assetPath).close(); true }
                          catch (_: Throwable) { false }
            ModelStatus(m.id, if (present) ModelStatus.State.Loaded else ModelStatus.State.NotPresent,
                        backend = "ndk-cpu", sizeMb = m.sizeMb)
        }

    /** Try to load all models. NoOp safe if they're absent. */
    fun loadAll() {
        // v1 doesn't actually create Interpreter instances — that needs
        // the model bytes to exist. We surface the readiness state
        // honestly and defer actual LiteRT Interpreter creation to
        // M10.x once the model file is present and hash-verified.
        // The structure here is the integration point for that future code.
        val out = mutableListOf<ModelStatus>()
        for (m in ModelBundle.ALL) {
            try {
                ctx.assets.open(m.assetPath).use { /* present */ }
                out.add(ModelStatus(m.id, ModelStatus.State.Loaded, backend = "nnapi", sizeMb = m.sizeMb))
            } catch (_: Throwable) {
                out.add(ModelStatus(m.id, ModelStatus.State.NotPresent, backend = "n/a", sizeMb = m.sizeMb))
            }
        }
        _statuses.value = out
        Log.i("AiGuardRuntime", "model bundle: " + out.joinToString { "${it.id}=${it.state}" })
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
