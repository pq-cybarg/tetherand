use crate::client::NymBuilder;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
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

/// Eager bootstrap: connect to the mixnet now and return our own
/// nym address (a 96-char base58 Recipient string). Returns null on
/// failure. Called from `NymHop.start()` if the user wants the
/// connect-time latency upfront rather than at first-dial.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeConnect<'local>(
    env: JNIEnv<'local>,
    _cls: JClass,
    handle: jlong,
) -> jni::objects::JString<'local> {
    if handle == 0 { return JString::default(); }
    let rt: &crate::client::NymRuntime = unsafe { &*(handle as *const _) };
    match rt.ensure_connected() {
        Ok(addr) => env.new_string(addr).unwrap_or_default(),
        Err(e) => { log::error!("nym connect: {e}"); JString::default() }
    }
}

/// Read one mixnet message (blocking up to 200 ms internally).
/// Returns the payload bytes, or an empty byte array on timeout /
/// no-message. Called by the Kotlin per-flow forwarder to receive
/// the exit-gateway's response chunks.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_NymHop_nativeRecv(
    env: JNIEnv,
    _cls: JClass,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 { return std::ptr::null_mut(); }
    let rt: &crate::client::NymRuntime = unsafe { &*(handle as *const _) };
    match rt.recv_one() {
        Ok(bytes) => {
            let arr = env.new_byte_array(bytes.len() as i32).unwrap();
            let signed: &[i8] = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, bytes.len()) };
            let _ = env.set_byte_array_region(&arr, 0, signed);
            arr.into_raw()
        }
        Err(_) => env.new_byte_array(0).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
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
    // Graceful disconnect before drop — the mixnet client sends a
    // forget-me message to the gateway so our session metadata is
    // cleared upstream. Then drop the box.
    let rt: &crate::client::NymRuntime = unsafe { &*(handle as *const _) };
    let _ = rt.disconnect();
    let _ = unsafe { Box::from_raw(handle as *mut crate::client::NymRuntime) };
}
