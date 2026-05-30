use crate::bridge::Bridge;
use crate::client::TorBuilder;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong};
use once_cell::sync::OnceCell;

static LOG_INIT: OnceCell<()> = OnceCell::new();

fn init_logger() {
    LOG_INIT.get_or_init(|| {
        #[cfg(feature = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("tetherand-tor")
                .with_max_level(log::LevelFilter::Info),
        );
    });
}

/// Init the Tor runtime. Returns a handle (Box::into_raw cast to i64);
/// 0 on error. `bridges_csv` is a comma-separated list of BridgeDB-
/// format lines. PT binary paths are optional — if a PT bridge is
/// requested without a corresponding path the build() returns a
/// config error which we log + return 0.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeInit(
    mut env: JNIEnv,
    _cls: JClass,
    cache_dir: JString,
    state_dir: JString,
    bridges_csv: JString,
    vanguards: jboolean,
    prefer_pq: jboolean,
    pt_bridge_path: JString,
    snowflake_path: JString,
    conjure_path: JString,
) -> jlong {
    init_logger();
    let cache: String = match env.get_string(&cache_dir) { Ok(s) => s.into(), Err(_) => return 0 };
    let state: String = match env.get_string(&state_dir) { Ok(s) => s.into(), Err(_) => return 0 };
    let csv: String = match env.get_string(&bridges_csv) { Ok(s) => s.into(), Err(_) => "".into() };
    let pt: String = env.get_string(&pt_bridge_path).map(Into::into).unwrap_or_default();
    let sf: String = env.get_string(&snowflake_path).map(Into::into).unwrap_or_default();
    let cj: String = env.get_string(&conjure_path).map(Into::into).unwrap_or_default();
    let bridges = csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|line| Bridge::parse(line).ok())
        .collect::<Vec<_>>();
    let mut b = TorBuilder::new(cache, state);
    b.bridges = bridges;
    b.vanguards = vanguards != 0;
    b.prefer_pq_handshake = prefer_pq != 0;
    if !pt.is_empty() { b.pt_bridge_path = Some(pt); }
    if !sf.is_empty() { b.snowflake_path = Some(sf); }
    if !cj.is_empty() { b.conjure_path = Some(cj); }
    match b.build() {
        Ok(rt) => Box::into_raw(Box::new(rt)) as jlong,
        Err(e) => { log::error!("tor init failed: {e}"); 0 }
    }
}

/// Dial host:port. Returns 0 on success, non-zero on error.
/// Start the embedded SOCKS5 listener on 127.0.0.1:0 and return the
/// chosen port (or -1 on failure). Idempotent: a second call returns
/// the existing port.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeStartSocks(
    _env: JNIEnv,
    _cls: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 { return -1; }
    let rt: &mut crate::client::TorRuntime = unsafe { &mut *(handle as *mut _) };
    match rt.start_socks() {
        Ok(p) => p as jint,
        Err(e) => { log::error!("socks start: {e}"); -1 }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeDial(
    mut env: JNIEnv,
    _cls: JClass,
    handle: jlong,
    host: JString,
    port: jint,
) -> jint {
    if handle == 0 { return -1; }
    let rt: &crate::client::TorRuntime = unsafe { &*(handle as *const _) };
    let host: String = match env.get_string(&host) { Ok(s) => s.into(), Err(_) => return -1 };
    match rt.dial(&host, port as u16) {
        Ok(()) => 0,
        Err(e) => { log::error!("tor dial failed: {e}"); -1 }
    }
}

/// No-op for v1 (stream lifecycle lives on the Kotlin side).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeClose(
    _env: JNIEnv,
    _cls: JClass,
    _handle: jlong,
    _stream_id: jlong,
) -> jint { 0 }

/// Drop the runtime + tokio + arti client.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_TorHop_nativeShutdown(
    _env: JNIEnv,
    _cls: JClass,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = unsafe { Box::from_raw(handle as *mut crate::client::TorRuntime) };
}
