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
}

mod tui;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TransportChoice { Adb, Tcp }

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
    }
}
