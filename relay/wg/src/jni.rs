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
