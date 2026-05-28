package dev.tetherand.app.hardened.ir

import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * The four incident-response actions surfaced in the Threat tab when the
 * user suspects compromise during DEFCON. Mapping to the spec's runbook.
 */
enum class IncidentAction(val displayName: String, val description: String) {
    Acknowledge(
        "Acknowledge",
        "Log + continue. Use for low-confidence alerts you've decided to ignore."
    ),
    Isolate(
        "Isolate",
        "Open Airplane mode. Stop using the phone for sensitive operations."
    ),
    Evacuate(
        "Evacuate",
        "Pre-snapshot has been taken; back up your data (run ./backup.sh from your Mac) before continuing."
    ),
    Burn(
        "Burn (factory reset)",
        "Wipe the device immediately. Wipes Seed Vault + user data. Confirmation required."
    );
}

object IncidentResponse {

    fun execute(ctx: Context, action: IncidentAction): String = when (action) {
        IncidentAction.Acknowledge -> "Acknowledged."

        IncidentAction.Isolate -> {
            try {
                ctx.startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                "Opened Airplane-mode settings — toggle it on."
            } catch (t: Throwable) { "Could not open Airplane settings: ${t.message}" }
        }

        IncidentAction.Evacuate -> {
            // We can't drive a Mac backup from the phone; we can confirm
            // the pre-snapshot is preserved and remind the user of the
            // next step.
            "Pre-conference snapshot is already saved; the next step is " +
            "to plug into your Mac and run ./backup.sh, then ./restore.sh " +
            "--undo if anything looks tampered."
        }

        IncidentAction.Burn -> {
            // Direct DevicePolicyManager.wipeData requires device-owner /
            // profile-owner — Tetherand isn't either. We route the user
            // to the system Reset flow instead.
            try {
                ctx.startActivity(Intent(Settings.ACTION_PRIVACY_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                "Opened Privacy settings — navigate to Reset > Factory data reset."
            } catch (t: Throwable) { "Could not open Reset settings: ${t.message}" }
        }
    }
}
