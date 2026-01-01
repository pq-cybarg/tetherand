#!/usr/bin/env bash
# tutorial.sh — serve the Tetherand DEFCON prep tutorial on http://localhost:7331/
#
# Generates a static HTML page with live status (ADB device, gnirehtet install,
# last backup, last attestation snapshot) and serves it locally. The page covers:
#   • Available tools (connect / backup / restore / defcon-prep) with commands
#   • Pre-DEFCON timeline (T-2w → arrival)
#   • Daily at-DEFCON checklist
#   • Departure + post-DEFCON workflow
#   • Hardware checklist with prices
#   • OPSEC absolute rules
#   • Threat model + defense coverage matrix
#   • AI-era threats (local-only-AI policy explicit)
#   • M0-M10 roadmap with status
#   • Incident response runbook
#   • References (AIMSICD, SnoopSnitch, NetMonster-core, Crocodile Hunter, Mullvad PQ, etc.)
#
# Usage:
#   ./tutorial.sh                 # serve on 127.0.0.1:7331, open browser
#   ./tutorial.sh --no-open       # don't open browser automatically
#   ./tutorial.sh --port 8000     # alternate port
#   ./tutorial.sh --regen         # regenerate HTML and exit (no server)
#
# Ctrl+C stops the server.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"
PORT=7331
OPEN_BROWSER=1
REGEN_ONLY=0

while (( $# )); do
  case "$1" in
    --no-open) OPEN_BROWSER=0; shift ;;
    --port)    PORT="$2"; shift 2 ;;
    --regen)   REGEN_ONLY=1; shift ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown $1" >&2; exit 1 ;;
  esac
done

OUT="$HERE/.tutorial-build"
mkdir -p "$OUT"

###############################################################################
# Live status gathering
###############################################################################
ST_DEVICE="(none connected)"
ST_DEVICE_OK=0
ST_GNIREHTET="not installed"
ST_GNIREHTET_OK=0
ST_VPN_GRANTED="(unknown)"
ST_BACKUP_COUNT=0
ST_BACKUP_LATEST="never"
ST_SNAPSHOT_LATEST="never"
ST_BASELINE_LATEST="never"
ST_ANDROID="?"
ST_SOC="?"

if serial=$("$ADB" devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1; exit}'); [[ -n "$serial" ]]; then
  ST_DEVICE_OK=1
  model=$("$ADB" -s "$serial" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
  ST_ANDROID=$("$ADB" -s "$serial" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
  ST_SOC=$("$ADB" -s "$serial" shell getprop ro.hardware 2>/dev/null | tr -d '\r')
  ST_DEVICE="${model:-?} · Android ${ST_ANDROID} · ${ST_SOC} · ${serial}"
  if "$ADB" -s "$serial" shell pm path com.genymobile.gnirehtet 2>/dev/null | grep -q package; then
    ST_GNIREHTET="installed"; ST_GNIREHTET_OK=1
    ST_VPN_GRANTED=$("$ADB" -s "$serial" shell cmd appops get com.genymobile.gnirehtet ACTIVATE_VPN 2>/dev/null | awk -F': ' '{print $2; exit}' | tr -d '\r')
  fi
fi
if [[ -d "$HERE/backups" ]]; then
  ST_BACKUP_COUNT=$(ls -1 "$HERE/backups"/*.tar.gz* 2>/dev/null | wc -l | tr -d ' ')
  if (( ST_BACKUP_COUNT > 0 )); then
    ST_BACKUP_LATEST=$(ls -1t "$HERE/backups"/*.tar.gz* 2>/dev/null | head -1 | xargs -I{} basename {})
  fi
fi
if [[ -d "$HERE/attestation/pre" ]];      then ST_SNAPSHOT_LATEST="pre-conference snapshot captured"; fi
if [[ -d "$HERE/attestation/post" ]];     then ST_SNAPSHOT_LATEST="$ST_SNAPSHOT_LATEST + post-conference snapshot"; fi
if compgen -G "$HERE/attestation/cell-baseline-*.jsonl" > /dev/null; then
  ST_BASELINE_LATEST=$(ls -1t "$HERE/attestation"/cell-baseline-*.jsonl 2>/dev/null | head -1 | xargs basename)
fi

NOW=$(date -u "+%Y-%m-%d %H:%M:%S UTC")

###############################################################################
# Write index.html with embedded CSS / JS, no external deps
###############################################################################
HTML="$OUT/index.html"
cat > "$HTML" <<'STATIC_HEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tetherand · DEFCON Prep</title>
<style>
  :root {
    --bg:        #0a0e14;
    --bg-2:      #11161d;
    --bg-3:      #161c24;
    --fg:        #c0c8d4;
    --fg-mute:   #6b7785;
    --fg-bright: #e6e6e6;
    --accent:    #00d68f;
    --accent-2:  #5cdfff;
    --warn:      #ffc857;
    --crit:      #ff5d62;
    --rule:      #1f2730;
    --code-bg:   #050709;
    --mono: ui-monospace, "SF Mono", "Menlo", "Monaco", "Cascadia Mono", "JetBrains Mono", monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.55 -apple-system, "SF Pro Text", system-ui, sans-serif; }
  body { min-height: 100vh; display: grid; grid-template-columns: 240px 1fr; }
  @media (max-width: 800px) { body { grid-template-columns: 1fr; } nav.side { position: static !important; } main { padding: 1.5rem 1rem !important; } }
  /* sidebar */
  nav.side { position: sticky; top: 0; align-self: start; height: 100vh; overflow-y: auto;
    background: var(--bg-2); border-right: 1px solid var(--rule); padding: 1.2rem 0.7rem; }
  nav.side h1 { color: var(--accent); font: 700 1.05rem var(--mono); margin: 0 0 0.2rem 0.5rem; letter-spacing: 0.04em; }
  nav.side .subtitle { color: var(--fg-mute); font-size: 0.78rem; margin: 0 0 1.2rem 0.5rem; }
  nav.side a { display: block; color: var(--fg); text-decoration: none; padding: 0.32rem 0.5rem; border-radius: 4px;
    font-size: 0.84rem; }
  nav.side a:hover { background: var(--bg-3); color: var(--accent-2); }
  nav.side a.crit { color: var(--crit); }
  /* main */
  main { padding: 2rem 2.4rem; max-width: 1100px; }
  h2 { color: var(--fg-bright); font: 700 1.3rem -apple-system, system-ui; margin: 2.5rem 0 0.7rem; padding-top: 0.5rem; border-top: 1px solid var(--rule); letter-spacing: -0.01em; }
  h2:first-of-type { border-top: none; margin-top: 1rem; }
  h3 { color: var(--accent-2); font: 600 0.98rem -apple-system, system-ui; margin: 1.4rem 0 0.4rem; letter-spacing: 0.02em; }
  p { margin: 0.5rem 0; }
  ul, ol { margin: 0.4rem 0 0.8rem 1.2rem; padding: 0; }
  li { margin: 0.2rem 0; }
  code, kbd { font-family: var(--mono); font-size: 0.86em; background: var(--code-bg); padding: 0.1em 0.4em; border-radius: 3px; color: var(--accent-2); border: 1px solid var(--rule); }
  /* status panel */
  .status { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.6rem; margin: 1rem 0 2rem; }
  .status .card { background: var(--bg-2); border: 1px solid var(--rule); border-radius: 6px; padding: 0.7rem 0.9rem; }
  .status .card .label { font-size: 0.72rem; color: var(--fg-mute); letter-spacing: 0.06em; text-transform: uppercase; }
  .status .card .value { font-family: var(--mono); font-size: 0.92rem; color: var(--fg-bright); margin-top: 0.2rem; word-break: break-all; }
  .ok    { color: var(--accent) !important; }
  .warn  { color: var(--warn) !important; }
  .crit  { color: var(--crit) !important; }
  .badge { display: inline-block; font-family: var(--mono); font-size: 0.74rem; padding: 0.1rem 0.5rem; border-radius: 3px;
    background: var(--bg-3); border: 1px solid var(--rule); margin-right: 0.4rem; vertical-align: middle; }
  .badge.ok   { color: var(--accent); border-color: rgba(0,214,143,0.4); }
  .badge.warn { color: var(--warn);   border-color: rgba(255,200,87,0.4); }
  .badge.crit { color: var(--crit);   border-color: rgba(255,93,98,0.4); }
  /* code block */
  pre { background: var(--code-bg); border: 1px solid var(--rule); border-left: 3px solid var(--accent);
    border-radius: 4px; padding: 0.7rem 0.9rem; margin: 0.6rem 0;
    font-family: var(--mono); font-size: 0.84rem; overflow-x: auto; color: var(--fg-bright); position: relative; }
  pre.danger { border-left-color: var(--crit); }
  pre.warn   { border-left-color: var(--warn); }
  pre button { position: absolute; top: 6px; right: 6px;
    background: var(--bg-3); border: 1px solid var(--rule); color: var(--fg); border-radius: 3px;
    font-family: var(--mono); font-size: 0.72rem; padding: 0.1rem 0.5rem; cursor: pointer; }
  pre button:hover { background: var(--bg); color: var(--accent); border-color: var(--accent); }
  pre button.copied { color: var(--accent); border-color: var(--accent); }
  /* tables */
  table { border-collapse: collapse; width: 100%; margin: 0.8rem 0; font-size: 0.86rem; }
  th, td { border: 1px solid var(--rule); padding: 0.45rem 0.6rem; vertical-align: top; text-align: left; }
  th { background: var(--bg-2); color: var(--fg-bright); font-weight: 600; }
  tr:nth-child(even) td { background: rgba(255,255,255,0.012); }
  /* tools grid */
  .tools { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.8rem; margin: 1rem 0; }
  .tool { background: var(--bg-2); border: 1px solid var(--rule); border-radius: 6px; padding: 1rem; }
  .tool h4 { margin: 0 0 0.3rem; color: var(--accent-2); font-family: var(--mono); font-size: 0.95rem; }
  .tool p { font-size: 0.86rem; color: var(--fg); margin: 0.2rem 0 0.5rem; }
  .tool code { display: block; padding: 0.4rem 0.6rem; font-size: 0.78rem; }
  /* timeline */
  .timeline { position: relative; padding-left: 1.4rem; margin: 1rem 0; }
  .timeline::before { content: ""; position: absolute; left: 6px; top: 0; bottom: 0; width: 2px; background: var(--rule); }
  .tl-item { position: relative; padding: 0.4rem 0 0.4rem 0.8rem; }
  .tl-item::before { content: ""; position: absolute; left: -1.4rem; top: 0.65rem; width: 12px; height: 12px;
    border-radius: 50%; background: var(--bg); border: 2px solid var(--accent); }
  .tl-item .when { color: var(--accent); font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.04em; text-transform: uppercase; }
  .tl-item .what { color: var(--fg-bright); font-size: 0.9rem; }
  /* notes */
  .note { background: var(--bg-2); border: 1px solid var(--rule); border-left: 3px solid var(--accent-2); padding: 0.7rem 0.9rem; margin: 0.7rem 0; border-radius: 4px; }
  .note.warn { border-left-color: var(--warn); }
  .note.crit { border-left-color: var(--crit); }
  .note strong { color: var(--fg-bright); }
  /* footer */
  footer { color: var(--fg-mute); margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule); font-size: 0.78rem; }
  a { color: var(--accent-2); }
  a:hover { color: var(--accent); }
  /* small toolbar */
  .toolbar { font-size: 0.75rem; color: var(--fg-mute); font-family: var(--mono); margin-top: 0.3rem; }
  /* print */
  @media print {
    body { grid-template-columns: 1fr; background: white; color: black; }
    nav.side { display: none; }
    pre, .status .card, .tool, .note { background: white; color: black; border-color: #ccc; }
    a { color: black; text-decoration: underline; }
  }
</style>
</head>
<body>
<nav class="side">
  <h1>TETHERAND</h1>
  <div class="subtitle">DEFCON prep · localhost:7331</div>
  <a href="#status">▸ Status</a>
  <a href="#tools">▸ Tools available</a>
  <a href="#timeline">▸ Timeline</a>
  <a href="#daily">▸ Daily at DEFCON</a>
  <a href="#hardware">▸ Hardware checklist</a>
  <a href="#opsec">▸ OPSEC rules</a>
  <a href="#threats">▸ Threat model</a>
  <a href="#coverage">▸ Defense coverage</a>
  <a href="#ai">▸ AI-era threats</a>
  <a href="#roadmap">▸ M0-M10 roadmap</a>
  <a href="#incident" class="crit">▸ Incident response</a>
  <a href="#refs">▸ References</a>
</nav>
<main>
  <h2 style="border-top:none;margin-top:0">DEFCON Prep · Tetherand</h2>
  <p>The Solana Seeker has cellular + Wi-Fi + Bluetooth + NFC + USB + biometrics + a hardware-backed Solana wallet. DEFCON has IMSI catchers, Pineapples, juice jackers, evil twins, BLE trackers, LLM-supercharged phishing, deepfake calls, and an audience explicitly trying to break things. This page is the playbook.</p>
  <p>Two principles run through everything:</p>
  <ul>
    <li><strong>Deterministic core, contributory AI.</strong> Every defense has a clear rule that drives the action. Local AI classifiers add nuance and catch novel patterns &mdash; never gate destructive actions.</li>
    <li><strong>Local-only AI.</strong> Every model runs on the Seeker's NPU. No prompt, classification, or telemetry ever reaches a cloud LLM API. The egress-LLM-API SNI watch enforces this for other apps too.</li>
  </ul>
STATIC_HEAD

# Live status section (templated with shell variables)
cat >> "$HTML" <<HTML_STATUS

  <h2 id="status">Status as of $NOW</h2>
  <div class="status">
    <div class="card">
      <div class="label">Device</div>
      <div class="value $( ((ST_DEVICE_OK)) && echo "ok" || echo "warn" )">${ST_DEVICE}</div>
    </div>
    <div class="card">
      <div class="label">Gnirehtet (stopgap APK)</div>
      <div class="value $( ((ST_GNIREHTET_OK)) && echo "ok" || echo "warn" )">${ST_GNIREHTET}</div>
    </div>
    <div class="card">
      <div class="label">VpnService consent</div>
      <div class="value">${ST_VPN_GRANTED:-not granted}</div>
    </div>
    <div class="card">
      <div class="label">Local backups</div>
      <div class="value">${ST_BACKUP_COUNT} archive(s)</div>
      <div class="toolbar">latest: ${ST_BACKUP_LATEST}</div>
    </div>
    <div class="card">
      <div class="label">Attestation snapshots</div>
      <div class="value">${ST_SNAPSHOT_LATEST}</div>
    </div>
    <div class="card">
      <div class="label">Cell-environment baseline</div>
      <div class="value">${ST_BASELINE_LATEST}</div>
    </div>
  </div>
HTML_STATUS

# Remainder of the page (no shell interpolation needed; uses literal $ in JS).
cat >> "$HTML" <<'STATIC_BODY'

  <h2 id="tools">Tools available today (M0)</h2>
  <p>Everything here works <em>now</em>, before any custom APK is built. Each script is reversible.</p>
  <div class="tools">
    <div class="tool">
      <h4>./connect.sh</h4>
      <p>Reverse-tether: share the Mac's network connection to the Seeker over USB. Built on upstream Gnirehtet; the custom multi-transport build (M1) replaces this later. Ctrl+C to disconnect.</p>
      <pre><code>./connect.sh
./connect.sh --stop
./connect.sh --dns 1.1.1.1</code><button onclick="copyCode(this)">copy</button></pre>
    </div>
    <div class="tool">
      <h4>./backup.sh</h4>
      <p>Full local AES-256-CBC + PBKDF2 encrypted backup: every setting, every installed APK, all <code>/sdcard</code> media, package signing fingerprints, permission grants, device fingerprint. SHA-256 manifest of every file. Limits documented in <code>--help</code>.</p>
      <pre><code>./backup.sh              # full
./backup.sh --light      # settings + APK list, fast
./backup.sh --media-only # just /sdcard
./backup.sh --no-encrypt # not recommended</code><button onclick="copyCode(this)">copy</button></pre>
    </div>
    <div class="tool">
      <h4>./restore.sh</h4>
      <p>Restore from a <code>backup.sh</code> archive. Manifest-verified, mode-restricted variants, captures a pre-restore snapshot so the restore itself is reversible (<code>--undo</code>).</p>
      <pre><code>./restore.sh                     # interactive picker
./restore.sh archive.tar.gz.enc
./restore.sh archive --settings-only
./restore.sh archive --apks-only
./restore.sh --undo</code><button onclick="copyCode(this)">copy</button></pre>
    </div>
    <div class="tool">
      <h4>./scripts/defcon-prep.sh</h4>
      <p>The pre-flight playbook. Attestation snapshot, ADB-driven hardening (LTE-only, NFC/BT off, network forget, permission audit, signing-cert snapshot), 30-minute cell-environment baseline driver, hardware checklist printout. Every change y/N-gated and reversible with <code>--restore</code>.</p>
      <pre><code>./scripts/defcon-prep.sh             # full pre-flight
./scripts/defcon-prep.sh --snapshot  # snapshot only
./scripts/defcon-prep.sh --baseline  # 30-min cell drive
./scripts/defcon-prep.sh --post      # diff vs pre
./scripts/defcon-prep.sh --restore   # undo settings changes</code><button onclick="copyCode(this)">copy</button></pre>
    </div>
    <div class="tool">
      <h4>./tutorial.sh (this page)</h4>
      <p>Regenerates and serves the playbook with live status. Re-run any time to refresh the status panel at the top.</p>
      <pre><code>./tutorial.sh
./tutorial.sh --port 8000
./tutorial.sh --no-open
./tutorial.sh --regen   # build HTML and exit</code><button onclick="copyCode(this)">copy</button></pre>
    </div>
  </div>

  <h2 id="timeline">Timeline</h2>
  <p>Work backwards from your DEFCON arrival date. The exact dates are yours to fill in; the relative offsets matter.</p>
  <div class="timeline">
    <div class="tl-item"><div class="when">Now</div><div class="what">Read this page. Read the spec at <code>docs/superpowers/specs/2026-05-26-tetherand-design.md</code>. Order hardware (see below). Review installed apps; uninstall anything you don't trust at DEFCON.</div></div>
    <div class="tl-item"><div class="when">T &minus; 2 weeks</div><div class="what">Run <code>./backup.sh</code> for a baseline backup. Update everything: OS, apps, firmware. Run <code>./scripts/defcon-prep.sh --snapshot</code> for the clean attestation snapshot. Install Mullvad VPN and Orbot if not already installed; configure Mullvad with PQ multihop, entry server <em>not</em> in Nevada.</div></div>
    <div class="tl-item"><div class="when">T &minus; 1 week</div><div class="what">Hardware arrived: test USB data blocker with a known-good cable. Pair YubiKey with your accounts. Charge your throwaway power bank. Run a Faraday-pouch signal-loss check. Move Solana primary keys off-device per the Seed Vault export flow; verify on-device vault is empty afterward.</div></div>
    <div class="tl-item"><div class="when">T &minus; 1 day</div><div class="what">Run <code>./backup.sh</code> again for a fresh pre-DEFCON snapshot. Run <code>./scripts/defcon-prep.sh</code> for the full pre-flight (LTE-only, NFC/BT off, network forget, permission audit). Confirm Mullvad <em>always-on + lockdown</em> is on in Android Settings &rarr; VPN. Disable biometrics, set a strong PIN. Disable USB debugging until you actually need the tether.</div></div>
    <div class="tl-item"><div class="when">Arrival day</div><div class="what">Pre-flight one more time. Run <code>./scripts/defcon-prep.sh --baseline</code> at the hotel and walk around the conference perimeter so the threat engine has ground-truth cell data. Phone in the Faraday pouch when not in active use.</div></div>
    <div class="tl-item"><div class="when">Daily at DEFCON</div><div class="what">See "Daily at DEFCON" below.</div></div>
    <div class="tl-item"><div class="when">Departure day</div><div class="what">Phone stays in Faraday pouch through the airport. Don't connect to airport Wi-Fi. Do not check the laptop bag.</div></div>
    <div class="tl-item"><div class="when">Home</div><div class="what">Before unlocking on home Wi-Fi: run <code>./scripts/defcon-prep.sh --post</code> for the post-snapshot + diff vs pre. Review every diff: new apps, new permissions, new CAs, new device admins, settings changes you didn't make. If anything is unexpected, jump to <a href="#incident">Incident Response</a>.</div></div>
  </div>

  <h2 id="daily">Daily at DEFCON</h2>
  <ul>
    <li>Phone in Faraday pouch whenever you're not actively using it.</li>
    <li>Mullvad always-on + lockdown verified before each unlock (Android shows a key icon in the status bar; if you don't see it, your traffic is leaking).</li>
    <li>No USB connections to anything except your own data blocker + own power bank.</li>
    <li>No "let me see your phone" handoffs.</li>
    <li>Keep the phone screen face-down when set on a table (shoulder-surfers, ceiling cameras, also stops some BLE side-channel work).</li>
    <li>Do not connect to <code>DEFCON-Open</code>, <code>DEFCON-Insecure</code>, hotel Wi-Fi, or any other untrusted network. Cellular through Mullvad only.</li>
    <li>Do not scan random QR codes on stickers, badges, or vendor swag without checking the URL first (Android shows the URL in the system QR scanner; copy it before opening).</li>
    <li>Treat your badge as adversarial &mdash; don't plug it into your phone or laptop.</li>
    <li>Pay cash inside the convention hall.</li>
    <li>If someone calls you and the voice sounds slightly off (cadence, micro-pauses, room tone), hang up and call back via a known-good channel (Signal, family member you've confirmed out-of-band).</li>
    <li>End of each day: phone in Faraday pouch for sleep. If you must charge, use your own wall charger into a known socket via the data blocker.</li>
  </ul>

  <h2 id="hardware">Hardware checklist</h2>
  <table>
    <tr><th>Item</th><th>~Price</th><th>Why</th></tr>
    <tr><td><strong>PortaPow USB-C Data Blocker</strong></td><td>$7</td><td>Defeats juice jacking. Physically removes the data pins. Bring two in case one is lost.</td></tr>
    <tr><td><strong>Mission Darkness NeoLok Faraday Pouch (phone size)</strong></td><td>$30</td><td>Tested signal-loss &gt;100 dB. Phone goes in whenever not in active use. Test it before you leave: put the phone in, call it &mdash; should go straight to voicemail.</td></tr>
    <tr><td><strong>YubiKey 5C NFC</strong></td><td>$55</td><td>Hardware 2FA that can't be SMS- or voice-spoofed. Pair with every account that supports WebAuthn before DEFCON.</td></tr>
    <tr><td><strong>RTL-SDR Blog V4 + USB-C OTG cable</strong></td><td>$35 + $8</td><td>Powers the optional Crocodile Hunter SDR mode (M7b) once the app ships. Even before that, useful for cellular environment recon.</td></tr>
    <tr><td><strong>Throwaway power bank (Anker PowerCore 10000)</strong></td><td>$22</td><td>Never plug into public USB or unknown sockets. Pre-charge before leaving.</td></tr>
    <tr><td><strong>Spare cable (USB-C C-to-C)</strong></td><td>$10</td><td>One you control, charge-only or paired with data blocker.</td></tr>
    <tr><td><strong>Paper backup of any irreplaceable seed phrase</strong></td><td>$0</td><td>Stored in your Faraday pouch or hotel safe. Not on the device, not in cloud notes, not photographed.</td></tr>
    <tr><td><strong>Single-purpose travel laptop (optional)</strong></td><td>varies</td><td>If carrying a laptop, ideally a freshly-imaged single-purpose machine. Don't bring your work laptop.</td></tr>
    <tr><td><strong>Spare clean SIM (optional)</strong></td><td>~$15</td><td>If your primary SIM is tied to high-value accounts, a throwaway SIM removes the SIM-swap blast radius.</td></tr>
  </table>

  <h2 id="opsec">OPSEC absolute rules</h2>
  <div class="note crit"><strong>Non-negotiable:</strong> these aren't best-practices, they're rules. Break any of them and you've given up the perimeter.</div>
  <ul>
    <li>PIN unlock only. No biometric unlock during DEFCON. Biometrics can be physically compelled in many jurisdictions; PINs typically cannot.</li>
    <li>No SMS or email 2FA for high-value accounts. YubiKey or TOTP app only.</li>
    <li>No plugging the phone into anything you didn't bring yourself.</li>
    <li>No charging cables from the conference, hotel room, vendor booth, or borrowed.</li>
    <li>No connecting to any Wi-Fi network at the conference. Cellular through Mullvad only.</li>
    <li>No "interesting" QR codes, NFC tags, badges, or USB drives picked up off any surface.</li>
    <li>No clipboard for sensitive data without confirming what's actually pasted.</li>
    <li>No leaving the phone unattended on a table, in a hotel room, or in checked baggage.</li>
    <li>No biometric face/touch unlock prompts approved &mdash; cancel and use PIN.</li>
    <li>If something feels off, it is.</li>
  </ul>

  <h2 id="threats">Threat model</h2>
  <p>DEFCON's hostile-network surface is significantly larger than the rest of the year. Threats we explicitly design for:</p>
  <ul>
    <li><strong>Cellular layer:</strong> IMSI catchers (Stingray, Crossbow, Hailstorm), silent SMS stalking, A5/0 (no-encryption) downgrade, fake-BTS pattern attacks, RAT downgrade (5G/LTE &rarr; UMTS/GSM), TAC churn re-attach attacks.</li>
    <li><strong>Wi-Fi layer:</strong> Pineapples on drones and in bags, KARMA (responding to your phone's probed-for-SSIDs), evil-twin SSIDs that mimic known networks, deauth floods to coerce reconnection, beacon floods, captive-portal coercion to install certificates.</li>
    <li><strong>Bluetooth layer:</strong> BLE trackers (AirTag, Tile, SmartTag, Pebblebee, Chipolo) attached to your bag, BlueBorne / RCE in BT stack, pairing-request floods, BT-name targeting.</li>
    <li><strong>NFC layer:</strong> Malicious tags on stickers / posters / badges, NFC-based wallet phishing.</li>
    <li><strong>USB layer:</strong> Juice-jacking (data extraction over charging cable), BadUSB (charger pretending to be a keyboard), undeclared OTG devices that look like power-only cables.</li>
    <li><strong>App layer:</strong> Targeted malware via clones of legitimate apps, accessibility-service persistence, device-admin persistence, rogue VPN profile injection, rogue root-CA injection.</li>
    <li><strong>Physical layer:</strong> Evil maid (someone touches your unattended phone), shoulder surfing, ceiling cameras, hot-pluggable forensic tools (Cellebrite / GrayKey), badge-as-implant.</li>
    <li><strong>Wallet layer (Seeker-specific):</strong> Targeted attacks on Solana Mobile Stack apps, Seed Vault drain attempts, malicious dApps in the dApp store.</li>
    <li><strong>AI-era (new this year):</strong> Real-time voice deepfakes of trusted contacts, LLM-personalised phishing leveraging your scraped OSINT, AI-generated SMS / RCS / IM with grammar and tone indistinguishable from real, AI-driven CAPTCHA bypass against your accounts, prompt-injection payloads in clipboard / QR / NFC / message previews, AI-supercharged spyware that exfiltrates more selectively, deepfake images / video with no watermark.</li>
  </ul>

  <h2 id="coverage">Defense coverage</h2>
  <p>Mapping of threat to deterministic-primary defense. Anything in the AI column is <em>contributory</em> only &mdash; never the sole trigger for blocking, wiping, or escalating.</p>
  <table>
    <tr><th>Threat</th><th>Primary defense (deterministic)</th><th>Contributory (local AI, advisory)</th></tr>
    <tr><td>IMSI catcher / Stingray</td><td>LTE-only forcing + NetMonster Tier 0 reflection + AIMSICD BTSAlgorithm + Crocodile Hunter heuristics + drive baseline; optional SDR for SIB/MIB analysis (M7b)</td><td>&mdash;</td></tr>
    <tr><td>Pineapple / evil twin</td><td>Forget all saved networks + Pineapple OUI signatures + deauth-flood count + always-on VPN lockdown</td><td>&mdash;</td></tr>
    <tr><td>Juice jacking</td><td>USB data-block when locked + VID/PID allowlist + power-trace anomaly + selfie on USB plug while locked</td><td>&mdash;</td></tr>
    <tr><td>BLE tracker / AirTag</td><td>BLE scan + same-MAC-across-geohashes persistence rule</td><td>&mdash;</td></tr>
    <tr><td>KARMA / probe-request leak</td><td>Forget all saved networks + probe-request minimization</td><td>&mdash;</td></tr>
    <tr><td>App impersonation</td><td>Signing-cert SHA snapshot + diff on every unlock</td><td>&mdash;</td></tr>
    <tr><td>Persistence: accessibility service / device admin / rogue CA / rogue VPN</td><td>List-freeze + alert on any change</td><td>&mdash;</td></tr>
    <tr><td>Cellular cipher downgrade (A5/0)</td><td>Encryption-indicator + MTK-RIL prop poll (Tier 1 over tether)</td><td>&mdash;</td></tr>
    <tr><td>Silent SMS stalking</td><td>Silent-SMS heuristic + SDR paging-storm (with SDR attached)</td><td>&mdash;</td></tr>
    <tr><td>DNS hijack</td><td>DoH through Privacy Chain + DNS sinkhole + RFC1918-leak detector</td><td>&mdash;</td></tr>
    <tr><td>TLS MITM</td><td>TLS-ClientHello / SNI / cert-chain inspection at IP layer + pinning audit (no MITM)</td><td>&mdash;</td></tr>
    <tr><td>Captive-portal coercion</td><td>VpnService lockdown blocks all non-chain traffic</td><td>&mdash;</td></tr>
    <tr><td>Ultrasonic ad-network tracking</td><td>FFT detector at 18-22 kHz</td><td>&mdash;</td></tr>
    <tr><td>Evil maid (physical)</td><td>Accelerometer tamper detect + selfie on failed unlock + boot-count attestation diff</td><td>&mdash;</td></tr>
    <tr><td>Coercion / compulsion</td><td>Decoy profile + YubiKey unlock + biometrics-off</td><td>&mdash;</td></tr>
    <tr><td>Solana wallet drain</td><td>Tx-signing 30s cool-down + Seed Vault freeze + recommend off-device keys for the conference</td><td>&mdash;</td></tr>
    <tr><td>AI voice deepfake on call</td><td>User-initiated "verify caller" Signal handshake + voiceprint exact-match against trusted-contact vault</td><td><code>voiceguard-v1</code> synthesis-artifact score</td></tr>
    <tr><td>LLM-personalised phishing</td><td>URL-reputation + phishing-keyword regex + sender-history + RCS-anomaly rules</td><td><code>phi-tetherand-3b-q4</code> verdict</td></tr>
    <tr><td>Adversarial QR / lure image</td><td>URL-pattern + reputation DB + perceptual-hash blocklist</td><td><code>qrguard-v1</code> perturbation score</td></tr>
    <tr><td>Prompt-injection in clipboard</td><td>Regex match against known injection scaffolds; strip or quarantine pre-paste</td><td>&mdash; (rule-only)</td></tr>
    <tr><td>Synthetic media (deepfake images / video)</td><td>C2PA / SynthID / Content Credentials signature verify</td><td>&mdash; (rule-only)</td></tr>
    <tr><td>LLM-supercharged spyware (calls home)</td><td>Outbound SNI match against <code>api.openai.com</code>, <code>api.anthropic.com</code>, <code>generativelanguage.googleapis.com</code>, etc.</td><td>&mdash; (rule-only)</td></tr>
    <tr><td>Covert NPU use by background app</td><td>MTK NPU sysfs watcher + foreground-state rule</td><td>&mdash;</td></tr>
    <tr><td>AI-driven 2FA spoofing</td><td>YubiKey-only 2FA enforced in Hardened Mode (no SMS / voice / email fallback)</td><td>&mdash;</td></tr>
    <tr><td>Targeted-OSINT preparation</td><td>HIBP / IntelligenceX query via Privacy Chain; visualize what an attacker can scrape</td><td>&mdash; (rule-only)</td></tr>
  </table>

  <h2 id="ai">AI-era threats &middot; local-only policy</h2>
  <div class="note warn"><strong>Hard constraint:</strong> all Tetherand AI inference runs on the Seeker's MediaTek NPU via LiteRT + NNAPI. No prompt, classification request, or telemetry ever reaches a cloud LLM API. Period. The egress-LLM-API SNI watch exists to enforce this for other apps.</div>
  <p>Why local-only:</p>
  <ul>
    <li><strong>Cloud LLM APIs are an exfiltration channel.</strong> Any feature that ships a message preview to a remote model is leaking that preview &mdash; even when the response is benign.</li>
    <li><strong>Cloud LLM APIs are an availability dependency.</strong> A defense that stops working when the network drops is not a defense for hostile networks.</li>
    <li><strong>Cloud LLM APIs are subject to TOS, jurisdiction, and content-moderation gating.</strong> A security tool that gets rate-limited or refused mid-conference is unfit for the threat model.</li>
  </ul>
  <p>How it works:</p>
  <ul>
    <li>Four INT4-quantised models bundled in-APK (~2.4 GB compressed): <code>phi-tetherand-3b-q4</code> (message intent), <code>voiceguard-v1</code> (call-audio synthesis-artifact detector), <code>textguard-v1</code> (LLM-generated-text classifier), <code>qrguard-v1</code> (adversarial-image perturbation detector).</li>
    <li>NNAPI delegate routes inference to the MediaTek NPU. Per-event inference budget: under 200 ms.</li>
    <li>Every classifier sits behind a deterministic rule (see the table above). The rule fires; the classifier weights confidence; the user sees a banner.</li>
    <li>Model updates: signed via cosign against a pinned public key shipped in the APK. Delivered only through the active Privacy Chain when one is on. No out-of-band update path.</li>
  </ul>

  <h2 id="roadmap">Roadmap (M0-M10)</h2>
  <table>
    <tr><th>M</th><th>Scope</th><th>Effort</th><th>State</th></tr>
    <tr><td><strong>M0</strong></td><td>Pre-flight scripts: <code>connect.sh</code>, <code>backup.sh</code>, <code>restore.sh</code>, <code>scripts/defcon-prep.sh</code>, <code>tutorial.sh</code> (this page). High-value Hardened Mode subset, reversible.</td><td>4-6 h</td><td><span class="badge ok">SHIPPED</span></td></tr>
    <tr><td><strong>M1</strong></td><td>Tether MVP: fork + rebrand, transport abstraction, USB-ADB + TCP transports, Compose Tether tab, <code>tetherand run</code> CLI. Replaces <code>connect.sh</code>.</td><td>10-14 h</td><td><span class="badge ok">SHIPPED</span></td></tr>
    <tr><td><strong>M2</strong></td><td>More transports: Bluetooth RFCOMM + USB-AOA, ratatui dashboard, LaunchAgent + IOKit USB watcher.</td><td>10-14 h</td><td><span class="badge warn">NEXT</span></td></tr>
    <tr><td><strong>M3</strong></td><td>Privacy chain core: hop interface, WireGuard generic hop (BoringTun via JNI), chain orchestrator, Privacy tab with chain visualizer.</td><td>14-18 h</td><td><span class="badge ok">SHIPPED</span></td></tr>
    <tr><td><strong>M4a-c</strong></td><td>Mullvad classic WG + PQ tunnel (ML-KEM-1024 hybrid) + AF_INET-only kill-switch.</td><td>~10 h</td><td><span class="badge ok">SHIPPED</span></td></tr>
    <tr><td><strong>M4d</strong></td><td>Mullvad multihop — entry server pairs with a separate exit server through Mullvad's bridge infrastructure.</td><td>~4 h</td><td><span class="badge warn">NEXT</span></td></tr>
    <tr><td><strong>M4e</strong></td><td>DAITA — Mullvad's Defense Against AI-guided Traffic Analysis (constant-bitrate padding + adaptive shaping).</td><td>~6 h</td><td>planned</td></tr>
    <tr><td><strong>M4f</strong></td><td>Obfuscation transports — QUIC over 443, Shadowsocks, UDP-over-TCP. User picks per-chain.</td><td>~6 h</td><td>planned</td></tr>
    <tr><td><strong>M4g</strong></td><td>Split-tunnel by app — per-UID exclusion list via VpnService.Builder.addDisallowedApplication.</td><td>~3 h</td><td>planned</td></tr>
    <tr><td><strong>M5</strong></td><td>NymVPN embedded via JNI, 2-hop entry/exit through Sphinx mixnet.</td><td>6-10 h</td><td>planned</td></tr>
    <tr><td><strong>M6</strong></td><td>Tor + all PT bridges (obfs4, snowflake, meek, conjure, webtunnel) + PQ flags + vanguards.</td><td>14-18 h</td><td>planned</td></tr>
    <tr><td><strong>M7a</strong></td><td>Threat MVP (no SDR): NetMonster Tier 0 + AIMSICD BTSAlgorithm + bundled OpenCellID + SnoopSnitch high-level + Crocodile Hunter phone-side heuristics + Wi-Fi/BT/app audit + per-location baseline + Threat tab.</td><td>20-26 h</td><td>planned</td></tr>
    <tr><td><strong>M7b</strong></td><td>SDR mode: librtlsdr-android + hackrf_android + LTE control-channel decoder, SIB/MIB analysis, paging-storm detection.</td><td>12-16 h</td><td>planned</td></tr>
    <tr><td><strong>M7c</strong></td><td>Root-tier path: <code>/proc/ccci_md1_*</code> reader, mdlog parser, AT-command via <code>/dev/ttyMT*</code>. Dormant unless rooted.</td><td>4-6 h</td><td>planned</td></tr>
    <tr><td><strong>M8</strong></td><td>Polish &amp; release: smoke tests, signed release APK, install scripts, README, perf tuning.</td><td>6-8 h</td><td>planned</td></tr>
    <tr><td><strong>M9</strong></td><td>Hardened Mode in-app: DEFCON Mode toggle, attestation diff UI, decoy listeners + honeytokens, BLE tracker scan, USB data-block + selfie traps, accelerometer tamper, Solana wallet firewall, ultrasonic listener, TLS-pinning audit, decoy profile + YubiKey unlock, incident-response runbook.</td><td>22-30 h</td><td>planned</td></tr>
    <tr><td><strong>M10</strong></td><td>AI-era defenses (local-only, contributory): deterministic primaries first, then 4-model classifier stack on NPU, prompt-injection clipboard scrubber, C2PA / SynthID provenance, OSINT exposure dashboard, NPU sysfs watcher, egress-LLM-API SNI watch.</td><td>26-34 h</td><td>planned</td></tr>
  </table>

  <h2 id="incident">If you suspect compromise</h2>
  <div class="note crit">If anything below feels true, stop using the phone for sensitive operations <strong>immediately</strong>. Move to a known-good device. Treat the Seeker as forensically contaminated until verified.</div>
  <h3>Signs</h3>
  <ul>
    <li>Battery drops faster than baseline by &gt; 20% for the same usage.</li>
    <li>Phone runs warm when idle / screen off.</li>
    <li>You see an unfamiliar app, certificate, accessibility service, device-admin, or VPN profile.</li>
    <li>Mullvad's key icon is gone from the status bar.</li>
    <li>A call's voice sounds slightly off from a known contact.</li>
    <li>A message uses your nickname or context only specific people know &mdash; from someone who shouldn't have that context.</li>
    <li>The phone moved from where you left it.</li>
    <li>USB cable plugged in that you don't remember plugging.</li>
    <li>A new root CA appears in trusted credentials.</li>
  </ul>
  <h3>Responses</h3>
  <ol>
    <li><strong>Acknowledge.</strong> Note the time, location, and exactly what you saw. Don't power-cycle yet &mdash; volatile memory has forensic value.</li>
    <li><strong>Isolate.</strong> Airplane mode. Stop using the phone for anything sensitive. Move the Seeker into the Faraday pouch.</li>
    <li><strong>Capture.</strong> Plug into your Mac, run <code>./scripts/defcon-prep.sh --post</code> for a now-snapshot. The diff vs pre is your evidence.</li>
    <li><strong>Decide.</strong> Three options:
      <ul>
        <li><strong>Recover</strong> &mdash; if the diff looks innocuous (a known app updated, a Wi-Fi you connected to): clean up and continue.</li>
        <li><strong>Restore</strong> &mdash; run <code>./restore.sh</code> with the pre-conference backup, then change every password and every 2FA seed from your known-good device.</li>
        <li><strong>Burn</strong> &mdash; factory reset (Settings &rarr; System &rarr; Reset options &rarr; Erase all data), wipe Seed Vault, rotate every credential, treat the device as forensically compromised. This is the right answer if anything in the diff is unaccounted for.</li>
      </ul>
    </li>
  </ol>
  <h3>Authority contact (do not skip)</h3>
  <p>If you believe you've been targeted by a state-level actor (real IMSI catcher, professional surveillance), file a report with the EFF (<a href="https://www.eff.org/issues/printers">eff.org</a>) and document for your own records. DEFCON's SOC also takes incident reports during the conference.</p>

  <h2 id="refs">References</h2>
  <ul>
    <li><a href="https://github.com/Genymobile/gnirehtet">Gnirehtet</a> &mdash; the upstream we fork for the tether subsystem.</li>
    <li><a href="https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector">AIMSICD</a> &mdash; classic non-root IMSI-catcher detector. Ported into M7a.</li>
    <li><a href="https://opensource.srlabs.de/projects/snoopsnitch">SnoopSnitch</a> &mdash; SRLabs' deeper detection; Qualcomm-only diag-mode not on the Seeker, but high-level heuristics ported.</li>
    <li><a href="https://github.com/mroczis/netmonster-core">NetMonster-core</a> &mdash; actively-maintained MediaTek-aware cell-info reflection library. Backbone of M7a's Tier 0 collection.</li>
    <li><a href="https://github.com/EFForg/crocodilehunter">Crocodile Hunter (EFF)</a> &mdash; phone-side data collector + heuristics + optional SDR pipeline. Ported into M7a + M7b.</li>
    <li><a href="https://mullvad.net/en/help/why-i-need-have-account">Mullvad</a> &mdash; native PQ tunnel + multihop + DAITA + obfuscation. Hop in M4.</li>
    <li><a href="https://nymtech.net/">NymVPN</a> &mdash; Sphinx-mixnet 2-hop. Hop in M5.</li>
    <li><a href="https://www.torproject.org/">Tor Project</a> &mdash; PT bridges and PQ flags. Hop in M6.</li>
    <li><a href="https://www.eff.org/issues/cell-tracking">EFF cell-tracking resources</a> &mdash; threat model background for the cellular layer.</li>
    <li><a href="https://www.defcon.org/">DEFCON</a> &mdash; the conference itself.</li>
  </ul>

  <footer>
    Generated by <code>./tutorial.sh</code>. Static page, refresh by re-running the script. Source spec: <code>docs/superpowers/specs/2026-05-26-tetherand-design.md</code>. Local-only AI is a hard constraint, not a recommendation.
  </footer>
</main>
<script>
  function copyCode(btn) {
    var pre = btn.closest('pre');
    var code = pre.querySelector('code');
    var text = code.innerText;
    navigator.clipboard.writeText(text).then(function() {
      var was = btn.innerText;
      btn.innerText = 'copied';
      btn.classList.add('copied');
      setTimeout(function() { btn.innerText = was; btn.classList.remove('copied'); }, 1500);
    });
  }
</script>
</body>
</html>
STATIC_BODY

if (( REGEN_ONLY )); then
  echo "Generated $HTML"
  exit 0
fi

###############################################################################
# Serve on localhost:$PORT
###############################################################################
PY=$(command -v python3 || command -v python)
[[ -n "$PY" ]] || { echo "error: python3 not found"; exit 1; }

# Lightweight ANSI status output for terminal.
c_grn=$'\033[32m'; c_cyn=$'\033[36m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
echo "${c_cyn}==>${c_rst} Tetherand DEFCON-prep tutorial"
echo "    page:    ${c_grn}http://localhost:${PORT}/${c_rst}"
echo "    source:  ${HTML}"
echo "    re-run:  ./tutorial.sh   ${c_yel}(refreshes the live status block)${c_rst}"
echo "    stop:    Ctrl+C"

if (( OPEN_BROWSER )); then
  ( sleep 0.6; command -v open >/dev/null && open "http://localhost:${PORT}/" || true ) &
fi

cd "$OUT"
exec "$PY" -m http.server "$PORT" --bind 127.0.0.1
