//! ML-KEM-1024 wrapper for Mullvad's PQ tunnel.

use ml_kem::MlKem1024;
use ml_kem::kem::{Decapsulate, Kem, KeyExport};
#[allow(unused_imports)]
use ml_kem::kem::{Encapsulate, TryKeyInit};
use ml_kem::ml_kem_1024::DecapsulationKey;
#[cfg(test)]
use ml_kem::ml_kem_1024::EncapsulationKey;

pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const CIPHERTEXT_BYTES: usize = 1568;
pub const SHARED_SECRET_BYTES: usize = 32;

pub struct KemKeypair {
    dk: DecapsulationKey,
    ek_bytes: Vec<u8>,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let (dk, ek) = <MlKem1024 as Kem>::generate_keypair();
        let ek_bytes = ek.to_bytes().as_slice().to_vec();
        Self { dk, ek_bytes }
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.ek_bytes
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_BYTES], String> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(format!(
                "ciphertext must be {CIPHERTEXT_BYTES} bytes, got {}",
                ciphertext.len()
            ));
        }
        let ss = self
            .dk
            .decapsulate_slice(ciphertext)
            .map_err(|e| format!("decap: {e:?}"))?;
        let mut out = [0u8; SHARED_SECRET_BYTES];
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_server_simulation() {
        let client = KemKeypair::generate();
        assert_eq!(client.public_bytes().len(), PUBLIC_KEY_BYTES);

        let ek = EncapsulationKey::new_from_slice(client.public_bytes())
            .expect("server can parse EK bytes");
        let (ct, server_ss) = ek.encapsulate();

        let ct_bytes: &[u8] = ct.as_ref();
        assert_eq!(ct_bytes.len(), CIPHERTEXT_BYTES);
        let client_ss = client.decapsulate(ct_bytes).unwrap();
        assert_eq!(client_ss.as_slice(), server_ss.as_slice());
        assert_eq!(client_ss.len(), 32);
    }

    #[test]
    fn rejects_bad_ciphertext_length() {
        let client = KemKeypair::generate();
        let bad = vec![0u8; 100];
        let err = client.decapsulate(&bad).unwrap_err();
        assert!(err.contains("must be"));
    }
}
