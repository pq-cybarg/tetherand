package dev.tetherand.app.transport

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Server-mode RFCOMM listener. The Mac side of the tether (the
 * `tetherand-transport-bt` crate) discovers the paired Seeker by
 * scanning for this UUID, then opens a frame stream.
 *
 * Service UUID matches the Rust side (transport-bt/src/lib.rs):
 *   7e7ae72d-0000-1000-8000-00805F9B34FB
 * — SPP base with the high-order 32 bits rewritten so it never
 * collides with stock SPP-using bridges.
 */
class BtRfcommServer(private val ctx: Context) {

    enum class State { Idle, Listening, Connected, PermissionDenied, BtUnavailable, Error }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    private var server: BluetoothServerSocket? = null
    private var socket: BluetoothSocket? = null
    private val _state = MutableStateFlow(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    fun start() {
        if (job?.isActive == true) return
        val adapter = BluetoothAdapter.getDefaultAdapter()
        if (adapter == null || !adapter.isEnabled) {
            _state.value = State.BtUnavailable
            return
        }
        job = scope.launch {
            try {
                val s = try {
                    adapter.listenUsingRfcommWithServiceRecord("Tetherand", TETHERAND_UUID)
                } catch (sec: SecurityException) {
                    Log.w(TAG, "BLUETOOTH_CONNECT permission required: ${sec.message}")
                    _state.value = State.PermissionDenied
                    return@launch
                }
                server = s
                _state.value = State.Listening
                val sock = try { s.accept() }
                           catch (t: Throwable) { Log.w(TAG, "accept: $t"); null }
                if (sock != null) {
                    socket = sock
                    _state.value = State.Connected
                    // The frame stream lives behind the M2 transport-mux
                    // patch — for now we just hold the socket so the Mac
                    // side's connect succeeds; the Android-side framer
                    // ships alongside the host CLI's bt-mux loop.
                }
            } catch (t: Throwable) {
                Log.w(TAG, "rfcomm: $t")
                _state.value = State.Error
            }
        }
    }

    fun stop() {
        try { socket?.close() } catch (_: Throwable) {}
        try { server?.close() } catch (_: Throwable) {}
        socket = null; server = null
        job?.cancel(); job = null
        scope.cancel()
        _state.value = State.Idle
    }

    companion object {
        private const val TAG = "BtRfcommServer"
        val TETHERAND_UUID: UUID = UUID.fromString("7e7ae72d-0000-1000-8000-00805F9B34FB")
    }
}
