use crate::client::NymBuilder;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong};
use once_cell::sync::OnceCell;

static LOG_INIT: OnceCell<()> = OnceCell::new();

fn init_logger() {
    LOG_INIT.get_or_init(|| {
        #[cfg(feature = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("tetherand-nym")
                .with_max_level(log::LevelFilter::Info),
        );
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeInit(
    mut env: JNIEnv,
    _cls: JClass,
    state_dir: JString,
    mnemonic: JString,
    entry_gateway: JString,
    exit_gateway: JString,
) -> jlong {
    init_logger();
    let state: String = match env.get_string(&state_dir) { Ok(s) => s.into(), Err(_) => return 0 };
    let mn:    String = env.get_string(&mnemonic).map(Into::into).unwrap_or_default();
    let eg:    String = env.get_string(&entry_gateway).map(Into::into).unwrap_or_default();
    let xg:    String = env.get_string(&exit_gateway).map(Into::into).unwrap_or_default();
    let mut b = NymBuilder::new(state);
    if !mn.is_empty() { b.mnemonic = Some(mn); }
    if !eg.is_empty() { b.entry_gateway = Some(eg); }
    if !xg.is_empty() { b.exit_gateway = Some(xg); }
    match b.build() {
        Ok(rt) => Box::into_raw(Box::new(rt)) as jlong,
        Err(e) => { log::error!("nym init failed: {e}"); 0 }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeDial(
    mut env: JNIEnv,
    _cls: JClass,
    handle: jlong,
    host: JString,
    port: jint,
) -> jint {
    if handle == 0 { return -1; }
    let rt: &crate::client::NymRuntime = unsafe { &*(handle as *const _) };
    let host: String = match env.get_string(&host) { Ok(s) => s.into(), Err(_) => return -1 };
    match rt.dial(&host, port as u16) {
        Ok(()) => 0,
        Err(e) => { log::error!("nym dial: {e}"); -1 }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeClose(
    _env: JNIEnv, _cls: JClass, _handle: jlong, _stream_id: jlong,
) -> jint { 0 }

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeShutdown(
    _env: JNIEnv, _cls: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    let _ = unsafe { Box::from_raw(handle as *mut crate::client::NymRuntime) };
}
