// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

// Tetherand local patch: digest 0.11 replaced `GenericArray` (from
// the `generic-array` crate, typenum-based) with `hybrid_array::Array`
// at the digest-output boundary. We could've made `EncryptionKeyDigest`
// the new `Array` type and matched the digest return type
// directly — but that would have broken every downstream caller
// that uses `GenericArray`-specific methods like
// `EncryptionKeyDigest::from_exact_iter` (one such caller is
// `nym-client-core-surb-storage`).
//
// Strategy: keep `EncryptionKeyDigest` as `GenericArray` (matching
// the legacy public API surface) and CONVERT at the boundary inside
// `compute_digest`. The conversion is a one-byte-array copy.
use nym_crypto::{
    OutputSizeUser, crypto_hash,
    generic_array::{GenericArray, typenum::Unsigned},
    symmetric::stream_cipher::{CipherKey, KeySizeUser, generate_key},
};
use nym_sphinx_params::{ReplySurbEncryptionAlgorithm, ReplySurbKeyDigestAlgorithm};
use rand::{CryptoRng, RngCore};
use std::fmt::{self, Display, Formatter};

pub type EncryptionKeyDigest =
    GenericArray<u8, <ReplySurbKeyDigestAlgorithm as OutputSizeUser>::OutputSize>;

pub type SurbEncryptionKeySize = <ReplySurbEncryptionAlgorithm as KeySizeUser>::KeySize;

#[derive(Clone, Copy, Debug)]
pub struct SurbEncryptionKey(CipherKey<ReplySurbEncryptionAlgorithm>);

#[derive(Debug)]
pub enum SurbEncryptionKeyError {
    BytesOfInvalidLengthError,
}

impl Display for SurbEncryptionKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SurbEncryptionKeyError::BytesOfInvalidLengthError => {
                write!(f, "provided bytes have invalid length")
            }
        }
    }
}

impl std::error::Error for SurbEncryptionKeyError {}

impl SurbEncryptionKey {
    /// Generates fresh pseudorandom key that is going to be used by the recipient of the message
    /// to encrypt payload of the reply. It is only generated when reply-SURB is attached.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        SurbEncryptionKey(generate_key::<ReplySurbEncryptionAlgorithm, _>(rng))
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SurbEncryptionKeyError> {
        if bytes.len() != SurbEncryptionKeySize::USIZE {
            return Err(SurbEncryptionKeyError::BytesOfInvalidLengthError);
        }

        Ok(SurbEncryptionKey(GenericArray::clone_from_slice(bytes)))
    }

    pub fn compute_digest(&self) -> EncryptionKeyDigest {
        // Boundary conversion: digest 0.11 returns `hybrid_array::Array<u8, N>`,
        // we exposes a `GenericArray<u8, N>` to preserve the public API
        // surface for downstream callers. Same N, same bytes, different
        // wrapper struct — `clone_from_slice` over the raw bytes copies
        // the contents without any deserialization.
        let new_array = crypto_hash::compute_digest::<ReplySurbKeyDigestAlgorithm>(&self.0);
        GenericArray::clone_from_slice(new_array.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn inner(&self) -> &CipherKey<ReplySurbEncryptionAlgorithm> {
        &self.0
    }
}
