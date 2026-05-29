// tetherand-pt — Tor Pluggable-Transport bridge binary.
//
// Speaks pt-spec.txt on stdin/stdout: arti spawns us as a child
// process, sets TOR_PT_CLIENT_TRANSPORTS=<csv>, and we print
// CMETHOD/CMETHODS-DONE lines back. For each protocol we open a local
// SOCKS5 server; arti dials it and we forward the dialed connection
// through the matching PT handler (obfs4 / meek / webtunnel).
//
// Snowflake + Conjure are NOT served here — they ship as separately
// cross-compiled Go upstream binaries (see scripts/build-pts-android.sh).

mod pt_protocol;
mod socks5;
mod obfs4;
mod meek;
mod webtunnel;

use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::init();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match pt_protocol::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                pt_protocol::emit_pt_log(&format!("fatal: {e}"));
                ExitCode::from(1)
            }
        }
    })
}
