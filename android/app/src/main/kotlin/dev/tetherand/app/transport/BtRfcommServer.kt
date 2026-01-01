package dev.tetherand.app.transport

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.os.Build
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
import java.io.Closeable
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID

/**
 * Server-mode RFCOMM listener. The Mac side of the tether (the
 * `tetherand-transport-bt` crate / `tetherand-bt-bridge` Swift
 * helper) discovers the paired Seeker by scanning for this UUID,
 * then opens a frame stream.
 *
 * Service UUID matches the Rust side (transport-bt/src/lib.rs):
 *   7e7ae72d-0000-1000-8000-00805F9B34FB
 * — SPP base with the high-order 32 bits rewritten so it never
 * collides with stock SPP-using bridges.
 *
 * **Mock mode.** Android emulators have no Bluetooth stack
 * (BluetoothAdapter.getDefaultAdapter() returns null), which would
 * leave the entire BT codepath unverifiable in the dev loop. When
 * the adapter is absent — or when the system property
 * `tetherand.bt.mock` is set to `1`/`true` — the server falls back
 * to a localhost TCP listener on [MOCK_PORT]. The byte-level
 * semantics of the listener are identical to the RFCOMM channel
 * (raw stream-of-bytes), so the rest of the pipeline runs unmodified
 * and the Mac CLI's `tetherand bt connect --mock <port>` form
 * exercises the same paths a real BT pairing would.
 */
class BtRfcommServer(private val ctx: Context) {

    enum class State { Idle, Listening, Connected, PermissionDenied, BtUnavailable, MockListening, MockConnected, Error }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    private var server: BluetoothServerSocket? = null
    private var socket: BluetoothSocket? = null
    private var mockServer: ServerSocket? = null
    private var mockSocket: Socket? = null
    private val _state = MutableStateFlow(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    /** True when the loopback-TCP fallback should be used instead
     *  of the real BluetoothServerSocket. Engaged when:
     *    - The system property `tetherand.bt.mock` is `1`/`true`
     *      (manual override), OR
     *    - We're running on an Android emulator (ranchu/goldfish
     *      hardware, or "generic" build fingerprint). The emulator
     *      exposes a stub BluetoothAdapter that rejects every
     *      BLUETOOTH_CONNECT-gated call, so the "no adapter"
     *      heuristic doesn't fire — we have to recognise the
     *      emulator host directly.
     *
     *  `tetherand.bt.mock=false`/`0` also lets a developer force
     *  the real-BT path on a host where the heuristic would
     *  otherwise mock. */
    fun shouldUseMock(): Boolean {
        val sysprop = System.getProperty("tetherand.bt.mock", "")
        if (sysprop.equals("1", true) || sysprop.equals("true", true)) return true
        if (sysprop.equals("0", true) || sysprop.equals("false", true)) return false
        val isEmulator = Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
                         Build.HARDWARE.contains("ranchu", ignoreCase = true) ||
                         Build.HARDWARE.contains("goldfish", ignoreCase = true)
        val adapter = BluetoothAdapter.getDefaultAdapter()
        // No adapter at all → must mock. Emulator (even with a stub
        // adapter) → mock so the dev loop can exercise the codepath.
        return isEmulator || adapter == null
    }

    fun start() {
        if (job?.isActive == true) return
        if (shouldUseMock()) {
            startMock()
            return
        }
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

    /**
     * Loopback-TCP fallback for emulators / hosts without a BT stack.
     * Listens on [MOCK_PORT] and treats the first accepting connection
     * as if it were an RFCOMM channel. The Mac CLI's
     * `tetherand bt connect --mock <port>` form runs an adb-reverse
     * port-mapping so its TCP connect lands here.
     */
    private fun startMock() {
        job = scope.launch {
            try {
                val srv = ServerSocket(MOCK_PORT)
                mockServer = srv
                _state.value = State.MockListening
                Log.i(TAG, "BT mock mode active — listening on 127.0.0.1:$MOCK_PORT")
                val sock = try { srv.accept() }
                           catch (t: Throwable) { Log.w(TAG, "mock accept: $t"); null }
                if (sock != null) {
                    mockSocket = sock
                    _state.value = State.MockConnected
                    Log.i(TAG, "BT mock client connected from ${sock.remoteSocketAddress}")
                }
            } catch (t: Throwable) {
                Log.w(TAG, "mock rfcomm: $t")
                _state.value = State.Error
            }
        }
    }

    fun stop() {
        closeQuietly(socket); closeQuietly(server)
        closeQuietly(mockSocket); closeQuietly(mockServer)
        socket = null; server = null; mockSocket = null; mockServer = null
        job?.cancel(); job = null
        scope.cancel()
        _state.value = State.Idle
    }

    private fun closeQuietly(c: Closeable?) { try { c?.close() } catch (_: Throwable) {} }

    companion object {
        private const val TAG = "BtRfcommServer"
        val TETHERAND_UUID: UUID = UUID.fromString("7e7ae72d-0000-1000-8000-00805F9B34FB")
        /** Loopback port the mock listener binds. Chosen to sit
         *  between the ADB-transport (31416) and TCP-transport
         *  (31417) ports so the three transports never collide. */
        const val MOCK_PORT = 31418
    }
}
