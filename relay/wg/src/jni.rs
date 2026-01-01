//! JNI bindings. Compiled only when targeting Android.

use std::sync::Arc;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};

use crate::{Action, WgPeerConfig, WgTunnel};
use std::net::SocketAddr;

fn copy_jba(env: &mut JNIEnv, src: &JByteArray) -> Vec<u8> {
    env.convert_byte_array(src).unwrap_or_default()
}

fn jba(env: &mut JNIEnv, src: &[u8]) -> jbyteArray {
    let arr = env.byte_array_from_slice(src).expect("alloc byte array");
    arr.into_raw()
}

fn action_to_jba(env: &mut JNIEnv, action: Action) -> jbyteArray {
    // Tagged byte array:
    //   byte 0: tag (0=Done, 1=SendToPeer, 2=WriteToTunV4, 3=WriteToTunV6, 4=Error)
    //   bytes 1..: payload
    let (tag, payload) = match action {
        Action::Done             => (0u8, Vec::new()),
        Action::SendToPeer(b)    => (1u8, b),
        Action::WriteToTunV4(b)  => (2u8, b),
        Action::WriteToTunV6(b)  => (3u8, b),
        Action::Error(s)         => (4u8, s.into_bytes()),
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag);
    out.extend_from_slice(&payload);
    jba(env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeNew(
    mut env: JNIEnv,
    _class: JClass,
    priv_key: JByteArray,
    peer_pub: JByteArray,
    psk: JByteArray,
    endpoint_host: JString,
    endpoint_port: jint,
    keepalive_secs: jint,
) -> jlong {
    let priv_bytes = copy_jba(&mut env, &priv_key);
    let peer_bytes = copy_jba(&mut env, &peer_pub);
    let psk_bytes  = copy_jba(&mut env, &psk);
    let host: String = env.get_string(&endpoint_host).map(|s| s.into()).unwrap_or_default();

    if priv_bytes.len() != 32 || peer_bytes.len() != 32 { return 0; }
    let mut pk = [0u8; 32]; pk.copy_from_slice(&priv_bytes);
    let mut pp = [0u8; 32]; pp.copy_from_slice(&peer_bytes);
    let preshared = if psk_bytes.len() == 32 {
        let mut k = [0u8; 32]; k.copy_from_slice(&psk_bytes); Some(k)
    } else { None };
    let endpoint = match format!("{host}:{endpoint_port}").parse::<SocketAddr>() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let cfg = WgPeerConfig {
        private_key: pk,
        address_cidr: String::new(),
        dns: vec![],
        peer_public_key: pp,
        preshared_key: preshared,
        allowed_ips: vec![],
        endpoint,
        persistent_keepalive_secs: if keepalive_secs > 0 { Some(keepalive_secs as u16) } else { None },
    };
    match WgTunnel::new(&cfg) {
        Ok(t) => {
            let boxed: Box<Arc<WgTunnel>> = Box::new(Arc::new(t));
            Box::into_raw(boxed) as jlong
        }
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeEncap(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jbyteArray {
    if handle == 0 { return action_to_jba(&mut env, Action::Error("null handle".into())); }
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    let bytes = copy_jba(&mut env, &packet);
    action_to_jba(&mut env, t.encapsulate(&bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDecap(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jbyteArray {
    if handle == 0 { return action_to_jba(&mut env, Action::Error("null handle".into())); }
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    let bytes = copy_jba(&mut env, &packet);
    action_to_jba(&mut env, t.decapsulate(&bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeUpdateTimers(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return action_to_jba(&mut env, Action::Done); }
    let t = unsafe { &*(handle as *const Arc<WgTunnel>) };
    action_to_jba(&mut env, t.update_timers())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeFree(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe {
        let _ = Box::from_raw(handle as *mut Arc<WgTunnel>);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeInitLog(
    _env: JNIEnv, _class: JClass,
) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
}

// ---- Mullvad / KEM bindings ----

use crate::KemKeypair;

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemGenerate(
    _env: JNIEnv, _class: JClass,
) -> jlong {
    let kp = Box::new(KemKeypair::generate());
    Box::into_raw(kp) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemPublicKey(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let kp = unsafe { &*(handle as *const KemKeypair) };
    jba(&mut env, kp.public_bytes())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemDecapsulate(
    mut env: JNIEnv, _class: JClass, handle: jlong, ciphertext: JByteArray,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let kp = unsafe { &*(handle as *const KemKeypair) };
    let ct = copy_jba(&mut env, &ciphertext);
    match kp.decapsulate(&ct) {
        Ok(ss) => jba(&mut env, &ss),
        Err(_) => jba(&mut env, &[]),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadPqClient_nativeKemFree(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe { let _ = Box::from_raw(handle as *mut KemKeypair); }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_mullvad_MullvadConfigBuilder_nativeGenerateX25519Keypair(
    mut env: JNIEnv, _class: JClass,
) -> jbyteArray {
    let (priv_key, pub_key) = crate::generate_x25519_keypair();
    let mut both = Vec::with_capacity(64);
    both.extend_from_slice(&priv_key);
    both.extend_from_slice(&pub_key);
    jba(&mut env, &both)
}

// ---- DAITA bindings ----

use crate::DaitaScheduler;

fn encode_daita_actions(actions: Vec<crate::PaddingAction>) -> Vec<u8> {
    // [count: u32 BE][(tag: u8 (1=send_padding, 2=block), bytes_or_ms: u32 BE)]*
    let mut out = Vec::with_capacity(4 + actions.len() * 5);
    out.extend_from_slice(&(actions.len() as u32).to_be_bytes());
    for a in actions {
        match a {
            crate::PaddingAction::SendPadding(sz) => {
                out.push(1);
                out.extend_from_slice(&(sz as u32).to_be_bytes());
            }
            crate::PaddingAction::BlockOutgoing(d) => {
                out.push(2);
                out.extend_from_slice(&(d.as_millis() as u32).to_be_bytes());
            }
        }
    }
    out
}

/// Maximum number of DAITA machines we accept per scheduler. The
/// Mullvad-published machine set ships with ~10 entries today; we cap
/// at 128 to reject obvious DoS attempts where a hostile JNI caller
/// passes a 10M-element array and exhausts memory before we even
/// validate the contents.
const MAX_DAITA_MACHINES: usize = 128;
/// Maximum bytes per individual machine definition. DAITA machines
/// are compact state-machine descriptions; the upstream set's largest
/// is ~4 KB. We cap at 64 KB per machine which leaves headroom for
/// experimental machines without enabling a 1-GB per-machine DoS.
const MAX_DAITA_MACHINE_BYTES: usize = 64 * 1024;

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDaitaNew(
    mut env: JNIEnv, _class: JClass,
    machines: jni::objects::JObjectArray,
) -> jlong {
    let n = match env.get_array_length(&machines) {
        Ok(v) if (v as usize) <= MAX_DAITA_MACHINES => v as usize,
        Ok(_) => return 0,   // over-cap — reject without allocating
        Err(_) => return 0,
    };
    let mut owned: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let elem = match env.get_object_array_element(&machines, i as i32) {
            Ok(o) => o, Err(_) => return 0
        };
        let arr: JByteArray = elem.into();
        // Per-element length check BEFORE copy_jba allocates.
        let elem_len = env.get_array_length(&arr).unwrap_or(0) as usize;
        if elem_len > MAX_DAITA_MACHINE_BYTES { return 0; }
        owned.push(copy_jba(&mut env, &arr));
    }
    let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
    match DaitaScheduler::new(&refs) {
        Ok(d) => Box::into_raw(Box::new(d)) as jlong,
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDaitaOnSent(
    mut env: JNIEnv, _class: JClass, handle: jlong, size: jint,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let d = unsafe { &*(handle as *const DaitaScheduler) };
    jba(&mut env, &encode_daita_actions(d.on_packet_sent(size as u16)))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDaitaOnRecv(
    mut env: JNIEnv, _class: JClass, handle: jlong, size: jint,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let d = unsafe { &*(handle as *const DaitaScheduler) };
    jba(&mut env, &encode_daita_actions(d.on_packet_recv(size as u16)))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDaitaTick(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let d = unsafe { &*(handle as *const DaitaScheduler) };
    jba(&mut env, &encode_daita_actions(d.tick()))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_WireGuardHop_nativeDaitaFree(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe { let _ = Box::from_raw(handle as *mut DaitaScheduler); }
}

// ---- Shadowsocks / QUIC transport bindings ----

use crate::{ShadowsocksTransport, QuicTransport, WgTransport};
use std::sync::OnceLock;

static OBFS_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn obfs_rt() -> &'static tokio::runtime::Runtime {
    OBFS_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("tokio rt")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_ShadowsocksSocket_nativeSsConnect(
    mut env: JNIEnv, _class: JClass,
    host: jni::objects::JString, port: jint,
    cipher: jni::objects::JString, password: jni::objects::JString,
) -> jlong {
    let host: String = env.get_string(&host).map(|s| s.into()).unwrap_or_default();
    let cipher: String = env.get_string(&cipher).map(|s| s.into()).unwrap_or_default();
    let password: String = env.get_string(&password).map(|s| s.into()).unwrap_or_default();
    let addr: SocketAddr = match format!("{host}:{port}").parse() { Ok(a) => a, Err(_) => return 0 };
    match obfs_rt().block_on(ShadowsocksTransport::connect(addr, &cipher, &password)) {
        Ok(t) => Box::into_raw(Box::new(t)) as jlong,
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_ShadowsocksSocket_nativeSsSend(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jint {
    if handle == 0 { return -1; }
    let t = unsafe { &*(handle as *const ShadowsocksTransport) };
    let bytes = copy_jba(&mut env, &packet);
    match obfs_rt().block_on(t.send(&bytes)) { Ok(_) => 0, Err(_) => -1 }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_ShadowsocksSocket_nativeSsRecv(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let t = unsafe { &*(handle as *const ShadowsocksTransport) };
    match obfs_rt().block_on(t.recv()) {
        Ok(b) => jba(&mut env, &b),
        Err(_) => jba(&mut env, &[]),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_ShadowsocksSocket_nativeSsClose(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe { let _ = Box::from_raw(handle as *mut ShadowsocksTransport); }
}

// QUIC

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_QuicSocket_nativeQuicConnect(
    mut env: JNIEnv, _class: JClass,
    host: jni::objects::JString, port: jint,
    server_name: jni::objects::JString,
) -> jlong {
    let host: String = env.get_string(&host).map(|s| s.into()).unwrap_or_default();
    let server_name: String = env.get_string(&server_name).map(|s| s.into()).unwrap_or_default();
    let addr: SocketAddr = match format!("{host}:{port}").parse() { Ok(a) => a, Err(_) => return 0 };
    match obfs_rt().block_on(QuicTransport::connect(addr, &server_name)) {
        Ok(t) => Box::into_raw(Box::new(t)) as jlong,
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_QuicSocket_nativeQuicSend(
    mut env: JNIEnv, _class: JClass, handle: jlong, packet: JByteArray,
) -> jint {
    if handle == 0 { return -1; }
    let t = unsafe { &*(handle as *const QuicTransport) };
    let bytes = copy_jba(&mut env, &packet);
    match obfs_rt().block_on(t.send(&bytes)) { Ok(_) => 0, Err(_) => -1 }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_QuicSocket_nativeQuicRecv(
    mut env: JNIEnv, _class: JClass, handle: jlong,
) -> jbyteArray {
    if handle == 0 { return jba(&mut env, &[]); }
    let t = unsafe { &*(handle as *const QuicTransport) };
    match obfs_rt().block_on(t.recv()) {
        Ok(b) => jba(&mut env, &b),
        Err(_) => jba(&mut env, &[]),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tetherand_app_chain_QuicSocket_nativeQuicClose(
    _env: JNIEnv, _class: JClass, handle: jlong,
) {
    if handle == 0 { return; }
    unsafe { let _ = Box::from_raw(handle as *mut QuicTransport); }
}
