//! Tetherand CLI: wraps the forked Gnirehtet relay core + adb-forward
//! lifecycle. M1 supports the USB-ADB transport (default) and a plain TCP
//! transport (LAN). Both delegate to the same `tetherand_relay_core::relay`
//! function, which speaks Gnirehtet's native wire format (back-to-back IPv4
//! packets delimited by the IPv4 header's own length field).

use std::path::PathBuf;
use std::process::Command;
use std::thread;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_ADB_PORT: u16 = 31416;
const DEFAULT_TCP_PORT: u16 = 31417;
const PACKAGE_NAME: &str = "dev.tetherand.app";

#[derive(Debug, Parser)]
#[command(name = "tetherand", version, about = "Tetherand reverse-tethering relay")]
struct Cli {
    #[arg(long, env = "RUST_LOG")]
    log: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Run {
        #[arg(long)] device: Option<String>,
        #[arg(long, value_enum, default_value_t = TransportChoice::Adb)]
        transport: TransportChoice,
        #[arg(long, default_value_t = DEFAULT_ADB_PORT)]
        port: u16,
    },
    Install   { #[arg(long)] device: Option<String> },
    Uninstall { #[arg(long)] device: Option<String> },
    Reinstall { #[arg(long)] device: Option<String> },
    Status,
    /// M2: launch the ratatui dashboard.
    Tui,
    /// M2 Bluetooth-RFCOMM subcommands (macOS only — bridges through
    /// `tetherand-bt-bridge`, a Swift helper compiled from
    /// `relay/cli/macos-bt-helper/`).
    #[command(subcommand)]
    Bt(BtCmd),
}

#[derive(Debug, Subcommand)]
enum BtCmd {
    /// List paired Bluetooth devices (delegates to IOBluetooth).
    List,
    /// Open RFCOMM to the named device, pipe its bytes to/from the
    /// `tetherand` relay core listening on `--port`.
    ///
    /// When `--mock` is set, skips the IOBluetooth helper entirely
    /// and instead bridges through `adb reverse tcp:31418 tcp:31418`
    /// to the Android-side [BtRfcommServer] in mock mode. Lets the
    /// dev loop exercise the entire BT codepath inside the
    /// emulator without a paired Seeker.
    Connect {
        #[arg(long)] device: String,
        #[arg(long, default_value_t = DEFAULT_TCP_PORT)] port: u16,
        #[arg(long)] mock: bool,
    },
}

mod tui;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TransportChoice { Adb, Tcp }

/// Resolve the path to the `tetherand-bt-bridge` Swift helper.
/// Looked up next to the running `tetherand` binary, then in
/// `./bin/` relative to CWD. Returns `None` on non-macOS hosts
/// since the helper has no Linux / Windows analogue.
fn bt_helper_path() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") { return None; }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("tetherand-bt-bridge");
            if candidate.exists() { return Some(candidate); }
        }
    }
    let cwd_local = PathBuf::from("bin/tetherand-bt-bridge");
    if cwd_local.exists() { return Some(cwd_local); }
    let cwd_rel = PathBuf::from("../bin/tetherand-bt-bridge");
    if cwd_rel.exists() { return Some(cwd_rel); }
    None
}

fn init_log(override_: Option<&str>) {
    let filter = override_
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::env::var("RUST_LOG").unwrap_or_else(|_| "tetherand=info,warn".into()));
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .try_init();
}

fn adb_path() -> String {
    std::env::var("ADB").unwrap_or_else(|_| "adb".into())
}

fn apk_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let next_to_binary = exe.parent().unwrap().join("tetherand.apk");
    if next_to_binary.is_file() { return Ok(next_to_binary); }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let in_bin = manifest_dir.join("../../bin/tetherand.apk");
    if in_bin.is_file() { return Ok(in_bin.canonicalize()?); }
    anyhow::bail!("tetherand.apk not found next to binary or under bin/")
}

fn run_adb(device: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new(adb_path());
    if let Some(d) = device { cmd.arg("-s").arg(d); }
    cmd.args(args);
    cmd.output().context("running adb")
}

fn adb_install(device: Option<&str>) -> Result<()> {
    let apk = apk_path()?;
    let apk_str = apk.to_string_lossy().to_string();
    let out = run_adb(device, &["install", "-r", &apk_str])?;
    if !out.status.success() {
        anyhow::bail!("adb install failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    info!("APK installed");
    Ok(())
}

fn adb_uninstall(device: Option<&str>) -> Result<()> {
    let _ = run_adb(device, &["uninstall", PACKAGE_NAME])?;
    info!("APK uninstalled (if present)");
    Ok(())
}

/// `adb reverse localabstract:tetherand tcp:<port>` — on the device side
/// adbd binds the abstract socket `tetherand`; when the device's
/// VpnService connects to it (via `LocalSocket("tetherand")`), adb routes
/// the connection back to the host's TCP port where our relay is listening.
///
/// This is the inverse of `adb forward`. Gnirehtet upstream uses the same
/// direction.
fn adb_reverse(device: Option<&str>, port: u16) -> Result<()> {
    let abs = "localabstract:tetherand".to_string();
    let tcp = format!("tcp:{port}");
    let out = run_adb(device, &["reverse", &abs, &tcp])?;
    if !out.status.success() {
        anyhow::bail!("adb reverse failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    info!("adb reverse localabstract:tetherand -> tcp:{port}");
    Ok(())
}

fn adb_remove_reverse(device: Option<&str>) -> Result<()> {
    let abs = "localabstract:tetherand".to_string();
    let _ = run_adb(device, &["reverse", "--remove", &abs])?;
    Ok(())
}

/// Fire the invisible Activity's START intent. The Activity itself
/// (`TetherandActivity`) checks `VpnService.prepare()`, then starts the
/// foreground service. Mirrors how upstream Gnirehtet launches.
fn adb_start_service(device: Option<&str>) -> Result<()> {
    let out = run_adb(device, &[
        "shell", "am", "start",
        "-a", "dev.tetherand.app.START",
        "-n", &format!("{PACKAGE_NAME}/.TetherandActivity"),
    ])?;
    if !out.status.success() {
        tracing::warn!("could not auto-start service: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

/// Tell the invisible Activity to stop the VPN.
fn adb_stop_service(device: Option<&str>) -> Result<()> {
    let _ = run_adb(device, &[
        "shell", "am", "start",
        "-a", "dev.tetherand.app.STOP",
        "-n", &format!("{PACKAGE_NAME}/.TetherandActivity"),
    ])?;
    Ok(())
}

fn cmd_run(device: Option<String>, transport: TransportChoice, port: u16) -> Result<()> {
    adb_install(device.as_deref())?;

    let port = match transport {
        TransportChoice::Adb => {
            adb_reverse(device.as_deref(), port)?;
            port
        }
        TransportChoice::Tcp => {
            if port == DEFAULT_ADB_PORT { DEFAULT_TCP_PORT } else { port }
        }
    };

    let _ = adb_start_service(device.as_deref());

    info!("Starting relay on 127.0.0.1:{port}");

    let device_for_ctrlc = device.clone();
    let port_for_ctrlc = port;
    thread::spawn(move || {
        let _ = ctrlc_handler(device_for_ctrlc, port_for_ctrlc);
    });

    tetherand_relay_core::relay(port)
        .map_err(|e| anyhow::anyhow!("relay error: {e}"))?;
    Ok(())
}

fn ctrlc_handler(device: Option<String>, port: u16) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    ::ctrlc::set_handler(move || { let _ = tx.send(()); })
        .context("installing SIGINT handler")?;
    let _ = rx.recv();
    info!("Ctrl+C received, tearing down");
    let _ = adb_stop_service(device.as_deref());
    let _ = adb_remove_reverse(device.as_deref());
    let _ = port; // unused in reverse mode
    std::process::exit(0);
}

fn cmd_status() -> Result<()> {
    let out = run_adb(None, &["devices", "-l"])?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    println!("tetherand v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn cmd_tui() -> Result<()> {
    use std::sync::{Arc, Mutex};
    let state = Arc::new(Mutex::new(tui::DashboardState::default()));
    // Seed with the current adb-attached devices + transport rows so the
    // dashboard isn't empty on first paint.
    {
        let mut s = state.lock().unwrap();
        s.transports.push(tui::TransportRow { name: "usb-adb".into(), connected: false, note: "adb forward".into() });
        s.transports.push(tui::TransportRow { name: "usb-aoa".into(), connected: false, note: "accessory mode".into() });
        s.transports.push(tui::TransportRow { name: "bt".into(),     connected: false, note: "RFCOMM".into() });
        s.transports.push(tui::TransportRow { name: "tcp".into(),    connected: false, note: "LAN 31417".into() });
        // Populate devices from `adb devices -l`.
        if let Ok(out) = run_adb(None, &["devices", "-l"]) {
            for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "device" {
                    s.devices.push(tui::DeviceRow {
                        serial: parts[0].to_string(),
                        model: parts.iter().find(|p| p.starts_with("model:")).map(|p| p.trim_start_matches("model:").to_string()).unwrap_or_default(),
                        transport: "usb-adb".into(),
                    });
                }
            }
        }
    }
    tui::run(state).map_err(|e| anyhow::anyhow!("tui: {e}"))
}

fn cmd_bt_list() -> Result<()> {
    let helper = bt_helper_path()
        .context("tetherand-bt-bridge not found — run relay/cli/macos-bt-helper/build.sh on a macOS host")?;
    let status = Command::new(&helper).arg("--list").status()
        .with_context(|| format!("spawning {}", helper.display()))?;
    if !status.success() {
        anyhow::bail!("{} --list exited {}", helper.display(), status);
    }
    Ok(())
}

fn cmd_bt_connect(device: String, port: u16, mock: bool) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::Stdio;

    if mock {
        return cmd_bt_connect_mock(device, port);
    }
    let helper = bt_helper_path()
        .context("tetherand-bt-bridge not found — run relay/cli/macos-bt-helper/build.sh on a macOS host")?;

    // Start the relay core in a background thread so it's listening
    // before the helper is told to connect. The relay binds to
    // 127.0.0.1:<port> and accepts ONE client connection — that
    // client is us (the BT-bridge pump below).
    let relay_port = port;
    thread::spawn(move || {
        if let Err(e) = tetherand_relay_core::relay(relay_port) {
            tracing::error!("relay core exited: {e}");
        }
    });
    // Brief wait so relay's listen() races ahead of our connect().
    // 50 ms is a lot longer than localhost socket-bind needs in
    // practice (~1 ms); generous margin avoids a TOCTOU race on
    // very-slow CI hosts.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Spawn the Swift helper. Its stdout is the read side from BT;
    // its stdin is the write side toward BT. Its stderr inherits
    // so the user can see SDP / open errors in real time.
    let mut child = Command::new(&helper)
        .arg("--device").arg(&device)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {} --device {}", helper.display(), device))?;
    info!("tetherand-bt-bridge spawned (pid {}) for device '{}'", child.id(), device);

    let mut helper_stdin = child.stdin.take().expect("piped stdin");
    let mut helper_stdout = child.stdout.take().expect("piped stdout");

    // Connect to relay-core.
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connecting to relay-core 127.0.0.1:{port}"))?;
    let tcp_clone = tcp.try_clone().context("dup'ing TCP socket")?;

    // helper_stdout → tcp_write (BT-from-device → relay-core)
    let h_to_relay = thread::spawn(move || -> Result<()> {
        let mut tcp = tcp_clone;
        let mut buf = [0u8; 4096];
        loop {
            let n = helper_stdout.read(&mut buf)?;
            if n == 0 { break; }
            tcp.write_all(&buf[..n])?;
        }
        Ok(())
    });

    // tcp_read → helper_stdin (relay-core → BT-to-device)
    let relay_to_h = thread::spawn(move || -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp.read(&mut buf)?;
            if n == 0 { break; }
            helper_stdin.write_all(&buf[..n])?;
        }
        Ok(())
    });

    // Wait for the helper to exit (e.g. user disconnects BT or
    // closes Tetherand on the Seeker) — whichever pump dies first
    // is signaled via Child::wait() below.
    let status = child.wait().context("waiting on tetherand-bt-bridge")?;
    let _ = h_to_relay.join();
    let _ = relay_to_h.join();
    if !status.success() {
        anyhow::bail!("tetherand-bt-bridge exited {status}");
    }
    Ok(())
}

/// Loopback port the Android-side [BtRfcommServer] binds in mock
/// mode. Must match BtRfcommServer.MOCK_PORT.
const BT_MOCK_PORT: u16 = 31418;

/// Mock-mode BT bridge: uses adb-reverse + a single TCP connection
/// instead of IOBluetooth. The byte-level semantics match the real
/// RFCOMM channel, so the rest of the pipeline (relay-core, frame
/// codec, transport-mux) is exercised identically.
fn cmd_bt_connect_mock(device: String, port: u16) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let _ = device;  // serial is informational for adb; bare `adb` works against the default device
    // 1. adb reverse so the emulator's 127.0.0.1:31418 (where the mock
    //    BtRfcommServer listens) is reachable from the Mac's
    //    127.0.0.1:31418.
    let adb_status = Command::new(adb_path())
        .args(["reverse", &format!("tcp:{BT_MOCK_PORT}"), &format!("tcp:{BT_MOCK_PORT}")])
        .status()
        .context("spawning adb reverse for BT mock")?;
    if !adb_status.success() {
        anyhow::bail!("adb reverse tcp:{BT_MOCK_PORT} failed; is the emulator attached?");
    }

    // 2. Start relay-core in a background thread.
    let relay_port = port;
    thread::spawn(move || {
        if let Err(e) = tetherand_relay_core::relay(relay_port) {
            tracing::error!("relay core exited: {e}");
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    // 3. Open the BT-mock TCP socket through adb. This is the
    //    moral equivalent of the IOBluetoothRFCOMMChannel in the
    //    real-BT path.
    let mut bt = TcpStream::connect(("127.0.0.1", BT_MOCK_PORT))
        .with_context(|| format!("connecting to BT-mock 127.0.0.1:{BT_MOCK_PORT} (adb-reversed to emulator)"))?;
    info!("BT mock connected to emulator 127.0.0.1:{BT_MOCK_PORT}");

    // 4. Open relay-core client socket.
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connecting to relay-core 127.0.0.1:{port}"))?;
    let tcp_clone = tcp.try_clone().context("dup'ing relay TCP socket")?;
    let bt_clone = bt.try_clone().context("dup'ing BT-mock TCP socket")?;

    // 5. Bidirectional byte pumps — same shape as the helper-based
    //    path in [cmd_bt_connect], just with TCP instead of stdio.
    let bt_to_relay = thread::spawn(move || -> Result<()> {
        let mut bt = bt_clone;
        let mut tcp = tcp_clone;
        let mut buf = [0u8; 4096];
        loop {
            let n = bt.read(&mut buf)?;
            if n == 0 { break; }
            tcp.write_all(&buf[..n])?;
        }
        Ok(())
    });
    let relay_to_bt = thread::spawn(move || -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp.read(&mut buf)?;
            if n == 0 { break; }
            bt.write_all(&buf[..n])?;
        }
        Ok(())
    });

    let _ = bt_to_relay.join();
    let _ = relay_to_bt.join();
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_log(cli.log.as_deref());
    match cli.cmd {
        Cmd::Run { device, transport, port } => cmd_run(device, transport, port),
        Cmd::Install   { device }            => adb_install(device.as_deref()),
        Cmd::Uninstall { device }            => adb_uninstall(device.as_deref()),
        Cmd::Reinstall { device }            => { adb_uninstall(device.as_deref())?; adb_install(device.as_deref()) }
        Cmd::Status                          => cmd_status(),
        Cmd::Tui                             => cmd_tui(),
        Cmd::Bt(BtCmd::List)                 => cmd_bt_list(),
        Cmd::Bt(BtCmd::Connect { device, port, mock }) => cmd_bt_connect(device, port, mock),
    }
}
