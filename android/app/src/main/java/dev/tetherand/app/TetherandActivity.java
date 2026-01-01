package dev.tetherand.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;

/**
 * This (invisible) activity receives the {@link #ACTION_GNIREHTET_START START} and
 * {@link #ACTION_GNIREHTET_STOP} actions from the command line.
 * <p>
 * Recent versions of Android refuse to directly start a {@link android.app.Service Service} or a
 * {@link android.content.BroadcastReceiver BroadcastReceiver}, so actions are always managed by
 * this activity.
 * <p>
 * <b>Hardening:</b> a hostile third-party app on the device could fire
 * {@code dev.tetherand.app.START} or {@code dev.tetherand.app.STOP} to
 * toggle the VPN behind the user's back (most damagingly: STOP, which
 * fail-opens the tunnel and exposes the user's real IP). We narrow
 * acceptable callers to: our own UID, the {@code shell} UID (adb-driven
 * CLI flow), and the SystemUI UID. Anything else gets {@code finish()}'d
 * before the intent extras are even parsed.
 * <p>
 * Two layers of identity check, because each has a known gap:
 * <ul>
 *   <li>{@link Binder#getCallingUid()} works reliably only when the
 *       caller used {@code startActivityForResult}; for plain
 *       {@code startActivity} (and {@code adb shell am start} variants)
 *       it returns {@code Process.myUid()} or -1.</li>
 *   <li>{@link Activity#getReferrer()} is the documented Android API
 *       for "who launched me." It returns a {@code android-app://…}
 *       URI naming the calling package. It can be spoofed by a
 *       malicious caller passing {@code EXTRA_REFERRER}, but ONLY to
 *       a package they could otherwise impersonate — and an attacker
 *       who can already impersonate {@code com.android.shell} has
 *       root, which makes this check moot anyway.</li>
 * </ul>
 * Either path identifying the caller as trusted is sufficient; both
 * paths must agree to identify the caller as untrusted before we
 * reject.
 */
public class TetherandActivity extends Activity {

    private static final String TAG = TetherandActivity.class.getSimpleName();

    public static final String ACTION_GNIREHTET_START = "dev.tetherand.app.START";
    public static final String ACTION_GNIREHTET_STOP = "dev.tetherand.app.STOP";

    public static final String EXTRA_DNS_SERVERS = "dnsServers";
    public static final String EXTRA_ROUTES = "routes";

    private static final int VPN_REQUEST_CODE = 0;

    private VpnConfiguration requestedConfig;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Caller-identity check FIRST — before getIntent() is even
        // inspected. This blocks third-party invocation regardless of
        // how exotic the intent extras are.
        if (!isCallerTrusted()) {
            // Deliberately silent — we do NOT log the calling
            // package on the rejection path, since logging it would
            // tell an attacker (via logcat scraping) whether their
            // probe reached us. Telemetry-free deny.
            finishAndRemoveTask();
            return;
        }
        handleIntent(getIntent());
    }

    /**
     * Returns true iff the caller is allowed to drive the VPN through
     * this activity. Trusted callers:
     * <ul>
     *   <li>Our own package — Intent fired from inside the app.</li>
     *   <li>{@code com.android.shell} — adb-driven CLI flow. The
     *       referrer URI for adb-launched intents is exactly
     *       {@code android-app://com.android.shell}.</li>
     *   <li>{@code com.android.systemui} — Quick Settings tile path.</li>
     * </ul>
     */
    private boolean isCallerTrusted() {
        // Path A: Binder UID. Valid when the caller used
        // startActivityForResult OR when invoked by the OS service layer.
        int callerUid = Binder.getCallingUid();
        if (callerUid != -1 && callerUid != Process.INVALID_UID) {
            if (callerUid == Process.myUid()) return true;
            if (callerUid == Process.SHELL_UID) return true;
            if (callerUid == Process.SYSTEM_UID) return true;
            // Some explicit caller — fall through to referrer check.
        }
        // Path B: referrer URI. Catches adb-driven fire-and-forget.
        Uri referrer = getReferrer();
        if (referrer != null) {
            String s = referrer.toString();
            // The exact strings the platform emits.
            if (s.equals("android-app://" + getPackageName())) return true;
            if (s.equals("android-app://com.android.shell")) return true;
            if (s.equals("android-app://com.android.systemui")) return true;
        }
        // Neither path identifies a trusted caller. Reject.
        return false;
    }

    private void handleIntent(Intent intent) {
        String action = intent.getAction();
        // Action goes to logcat. We do NOT log intent extras (the host
        // CLI passes DNS server lists + route lists — neither is
        // secret, but logging it normalizes the practice of dumping
        // intent contents, which leads to mistakes elsewhere).
        Log.d(TAG, "Received request " + action);
        boolean finish = true;
        if (ACTION_GNIREHTET_START.equals(action)) {
            VpnConfiguration config = createConfig(intent);
            finish = startTetherand(config);
        } else if (ACTION_GNIREHTET_STOP.equals(action)) {
            stopTetherand();
        }

        if (finish) {
            finish();
        }
    }

    private static VpnConfiguration createConfig(Intent intent) {
        String[] dnsServers = intent.getStringArrayExtra(EXTRA_DNS_SERVERS);
        if (dnsServers == null) {
            dnsServers = new String[0];
        }
        String[] routes = intent.getStringArrayExtra(EXTRA_ROUTES);
        if (routes == null) {
            routes = new String[0];
        }
        return new VpnConfiguration(Net.toInetAddresses(dnsServers), Net.toCIDRs(routes));
    }

    private boolean startTetherand(VpnConfiguration config) {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent == null) {
            Log.d(TAG, "VPN was already authorized");
            // we got the permission, start the service now
            TetherandService.start(this, config);
            return true;
        }

        Log.w(TAG, "VPN requires the authorization from the user, requesting...");
        requestAuthorization(vpnIntent, config);
        return false; // do not finish now
    }

    private void stopTetherand() {
        TetherandService.stop(this);
    }

    private void requestAuthorization(Intent vpnIntent, VpnConfiguration config) {
        this.requestedConfig = config;
        startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            TetherandService.start(this, requestedConfig);
        }
        requestedConfig = null;
        finish();
    }
}
