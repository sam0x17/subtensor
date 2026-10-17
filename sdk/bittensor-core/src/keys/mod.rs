//! Substrate `sp-core` key primitives (absorbed from `py-sp-core`).
//!
//! Keypair derivation, signing, verification, sealed-box encryption, and
//! SS58 codec — built against the same `sp-core` revision as the runtime, so
//! client crypto can never drift from the chain's.

// Client-side code: slicing and arithmetic on locally validated buffers is
// the norm here, and this crate never runs inside the runtime.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use codec::Encode;
use ed25519_zebra::{SigningKey, VerificationKey};
#[cfg(feature = "host")]
use sodiumoxide::crypto::box_;
#[cfg(feature = "host")]
use sodiumoxide::crypto::sealedbox;
#[cfg(feature = "host")]
use sodiumoxide::crypto::sign::ed25519 as sign_ed25519;
use sp_core::crypto::{
    AccountId32, CryptoType, DeriveError, DeriveJunction, Pair as PairT, SecretStringError,
    Ss58Codec,
};
use sp_core::{ed25519, sr25519, ByteArray};
use zeroize::Zeroizing;

use crate::error::CoreError;

mod base58;
#[cfg(feature = "host")]
mod encrypted_json;

/// Crypto type codes, matching the py-substrate-interface / btwallet convention.
pub const CRYPTO_ED25519: u8 = 0;
pub const CRYPTO_SR25519: u8 = 1;

pub const DEFAULT_SS58_FORMAT: u16 = 42;

fn crypto_err(msg: impl Into<String>) -> CoreError {
    CoreError::Crypto(msg.into())
}

#[cfg(feature = "host")]
pub(crate) fn ensure_sodium() -> Result<(), CoreError> {
    sodiumoxide::init().map_err(|_| crypto_err("failed to initialize libsodium"))?;
    Ok(())
}

// sp-core's CryptoBytes has several AsRef impls; pin down the byte view.
fn as_bytes<T: AsRef<[u8]>>(value: &T) -> Vec<u8> {
    value.as_ref().to_vec()
}

pub fn public_key_from_ss58(ss58_address: &str) -> Result<[u8; 32], CoreError> {
    let account = AccountId32::from_ss58check(ss58_address)
        .map_err(|e| crypto_err(format!("invalid ss58 address: {e:?}")))?;
    Ok(account.into())
}

/// ss58 rendering, byte-identical to sp-core's `to_ss58check_with_version`
/// but ~6x faster (see `base58.rs`); every decoded account id goes through
/// here, thousands per storage-map page / metagraph payload.
pub fn ss58_from_public(public_key: [u8; 32], ss58_format: u16) -> String {
    // "SS58PRE" ++ prefix (1-2 bytes) ++ key (32) ++ checksum (2)
    let mut buf = [0u8; 7 + 2 + 32 + 2];
    buf[..7].copy_from_slice(b"SS58PRE");
    let ident = ss58_format & 0b0011_1111_1111_1111;
    let prefix_len = if ident < 64 {
        buf[7] = ident as u8;
        1
    } else {
        // Two-byte prefix encoding per the ss58 registry spec.
        buf[7] = (((ident & 0b0000_0000_1111_1100) >> 2) as u8) | 0b0100_0000;
        buf[8] = ((ident >> 8) as u8) | (((ident & 0b11) as u8) << 6);
        2
    };
    buf[7 + prefix_len..7 + prefix_len + 32].copy_from_slice(&public_key);
    let body_end = 7 + prefix_len + 32;
    let checksum = sp_core::hashing::blake2_512(&buf[..body_end]);
    buf[body_end] = checksum[0];
    buf[body_end + 1] = checksum[1];
    base58::base58_encode(&buf[7..body_end + 2])
}

fn verify_with_crypto(
    crypto_type: u8,
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CoreError> {
    match crypto_type {
        CRYPTO_SR25519 => {
            let public = sr25519::Public::from_raw(*public_key);
            let sig = sr25519::Signature::from_slice(signature)
                .map_err(|_| crypto_err("invalid sr25519 signature length"))?;
            Ok(sr25519::Pair::verify(&sig, message, &public))
        }
        CRYPTO_ED25519 => {
            let public = ed25519::Public::from_raw(*public_key);
            let sig = ed25519::Signature::from_slice(signature)
                .map_err(|_| crypto_err("invalid ed25519 signature length"))?;
            Ok(ed25519::Pair::verify(&sig, message, &public))
        }
        other => Err(crypto_err(format!("unknown crypto type {other}"))),
    }
}

#[cfg(feature = "host")]
fn ed25519_to_x25519_pk(public_key: &[u8; 32]) -> Result<box_::PublicKey, CoreError> {
    ensure_sodium()?;
    let ed25519_pk = sign_ed25519::PublicKey::from_slice(public_key)
        .ok_or_else(|| crypto_err("invalid ed25519 public key"))?;
    sign_ed25519::to_curve25519_pk(&ed25519_pk)
        .map_err(|_| crypto_err("failed to convert ed25519 public key to x25519"))
}

fn ed25519_seed(pair: &Zeroizing<SigningKey>) -> &[u8] {
    let pair: &SigningKey = pair;
    pair.as_ref()
}

fn ed25519_public(pair: &Zeroizing<SigningKey>) -> [u8; 32] {
    let pair: &SigningKey = pair;
    VerificationKey::from(pair).into()
}

#[cfg(feature = "host")]
fn ed25519_x25519_from_pair(
    pair: &Zeroizing<SigningKey>,
) -> Result<(box_::PublicKey, box_::SecretKey), CoreError> {
    ensure_sodium()?;
    let seed = sign_ed25519::Seed::from_slice(ed25519_seed(pair))
        .ok_or_else(|| crypto_err("failed to derive x25519 keypair for decryption"))?;
    let (pk, sk) = sign_ed25519::keypair_from_seed(&seed);
    let x25519_pk = sign_ed25519::to_curve25519_pk(&pk)
        .map_err(|_| crypto_err("failed to derive x25519 keypair for decryption"))?;
    let x25519_sk = sign_ed25519::to_curve25519_sk(&sk)
        .map_err(|_| crypto_err("failed to derive x25519 keypair for decryption"))?;
    Ok((x25519_pk, x25519_sk))
}

struct WipingSeed(Zeroizing<[u8; 32]>);

impl Default for WipingSeed {
    fn default() -> Self {
        Self(Zeroizing::new([0; 32]))
    }
}

impl Clone for WipingSeed {
    fn clone(&self) -> Self {
        let mut clone = Self::default();
        clone.as_mut().copy_from_slice(self.as_ref());
        clone
    }
}

impl AsRef<[u8]> for WipingSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for WipingSeed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

/// Internal Ed25519 derivation owner. Both its seed and expanded signing key
/// erase themselves on every return, error, panic, and final drop path.
struct WipingEd25519Pair {
    secret: Zeroizing<SigningKey>,
}

impl WipingEd25519Pair {
    fn into_secret(self) -> Zeroizing<SigningKey> {
        self.secret
    }

    fn seed(&self) -> WipingSeed {
        let mut seed = WipingSeed::default();
        seed.as_mut().copy_from_slice(ed25519_seed(&self.secret));
        seed
    }
}

impl CryptoType for WipingEd25519Pair {
    type Pair = Self;
}

impl PairT for WipingEd25519Pair {
    type Public = ed25519::Public;
    type Seed = WipingSeed;
    type Signature = ed25519::Signature;

    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
        let secret =
            SigningKey::try_from(seed).map_err(|_| SecretStringError::InvalidSeedLength)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
        })
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), DeriveError> {
        let mut seed = self.seed();
        for junction in path {
            match junction {
                DeriveJunction::Soft(_) => return Err(DeriveError::SoftKeyInPath),
                DeriveJunction::Hard(chain_code) => {
                    let derived = Zeroizing::new(
                        ("Ed25519HDKD", &*seed.0, chain_code)
                            .using_encoded(sp_core::hashing::blake2_256),
                    );
                    seed.0.copy_from_slice(&derived);
                }
            }
        }
        Ok((Self::from_seed(&seed), Some(seed)))
    }

    fn public(&self) -> Self::Public {
        ed25519::Public::from_raw(ed25519_public(&self.secret))
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        Self::Signature::from_raw(self.secret.sign(message).to_bytes())
    }

    fn verify<M: AsRef<[u8]>>(
        signature: &Self::Signature,
        message: M,
        public: &Self::Public,
    ) -> bool {
        ed25519::Pair::verify(signature, message, public)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        ed25519_seed(&self.secret).to_vec()
    }
}

// Each Keypair holds exactly one variant; the size skew between ed25519 and
// public-only is irrelevant here.
#[allow(clippy::large_enum_variant)]
pub enum KeypairInner {
    Ed25519(Zeroizing<SigningKey>),
    Sr25519(sr25519::Pair),
    PublicOnly {
        public_key: [u8; 32],
        crypto_type: u8,
    },
}

impl KeypairInner {
    fn private_key_bytes(&self) -> Option<Vec<u8>> {
        match self {
            KeypairInner::Ed25519(pair) => Some(ed25519_seed(pair).to_vec()),
            KeypairInner::Sr25519(pair) => Some(pair.to_raw_vec()),
            KeypairInner::PublicOnly { .. } => None,
        }
    }
}

/// An sr25519 or ed25519 keypair backed by the workspace's sp-core.
pub struct Keypair {
    inner: KeypairInner,
    ss58_format: u16,
    /// The BIP39 phrase this keypair was derived from, when known and
    /// sufficient on its own to re-derive the key (no derivation password).
    /// Written to keyfiles as ``secretPhrase`` for parity with the legacy
    /// btwallet format that third-party tools parse.
    mnemonic: Option<Zeroizing<String>>,
    /// The raw seed this keypair was derived from, when known. Written to
    /// keyfiles as ``secretSeed`` (legacy-format parity).
    seed: Option<Zeroizing<Vec<u8>>>,
}

impl Keypair {
    /// Public-only or full keypair from SS58 address and/or raw public key bytes.
    pub fn new(
        ss58_address: Option<&str>,
        public_key: Option<&[u8]>,
        crypto_type: u8,
        ss58_format: u16,
    ) -> Result<Self, CoreError> {
        match crypto_type {
            CRYPTO_SR25519 | CRYPTO_ED25519 => {}
            other => return Err(crypto_err(format!("unknown crypto type {other}"))),
        }

        let public_key = match (ss58_address, public_key) {
            (Some(addr), None) => public_key_from_ss58(addr)?,
            (None, Some(pk)) => <[u8; 32]>::try_from(pk)
                .map_err(|_| crypto_err("public key must be exactly 32 bytes"))?,
            (Some(addr), Some(pk)) => {
                let from_addr = public_key_from_ss58(addr)?;
                let from_pk = <[u8; 32]>::try_from(pk)
                    .map_err(|_| crypto_err("public key must be exactly 32 bytes"))?;
                if from_addr != from_pk {
                    return Err(crypto_err(
                        "ss58 address and public key refer to different accounts",
                    ));
                }
                from_pk
            }
            (None, None) => {
                return Err(crypto_err(
                    "no ss58 formatted address or public key provided",
                ));
            }
        };

        Ok(Self {
            inner: KeypairInner::PublicOnly {
                public_key,
                crypto_type,
            },
            ss58_format,
            mnemonic: None,
            seed: None,
        })
    }

    /// Derive a keypair from a BIP39 mnemonic (with optional password).
    pub fn from_mnemonic(
        mnemonic: &str,
        crypto_type: u8,
        password: Option<&str>,
    ) -> Result<Self, CoreError> {
        let (inner, seed) = match crypto_type {
            CRYPTO_SR25519 => {
                let (pair, seed) = sr25519::Pair::from_phrase(mnemonic, password)
                    .map_err(|e| crypto_err(format!("invalid mnemonic: {e:?}")))?;
                (KeypairInner::Sr25519(pair), Zeroizing::new(seed.to_vec()))
            }
            CRYPTO_ED25519 => {
                let (pair, seed) = WipingEd25519Pair::from_phrase(mnemonic, password)
                    .map_err(|e| crypto_err(format!("invalid mnemonic: {e:?}")))?;
                (
                    KeypairInner::Ed25519(pair.into_secret()),
                    Zeroizing::new(seed.as_ref().to_vec()),
                )
            }
            other => return Err(crypto_err(format!("unknown crypto type {other}"))),
        };
        Ok(Self {
            inner,
            ss58_format: DEFAULT_SS58_FORMAT,
            // A phrase with a derivation password cannot re-derive the key on
            // its own, so only a passwordless phrase is kept (and written to
            // keyfiles); the derived seed is always sufficient.
            mnemonic: password
                .is_none()
                .then(|| Zeroizing::new(mnemonic.to_string())),
            seed: Some(seed),
        })
    }

    /// Derive a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8], crypto_type: u8) -> Result<Self, CoreError> {
        let inner = match crypto_type {
            CRYPTO_SR25519 => KeypairInner::Sr25519(
                sr25519::Pair::from_seed_slice(seed)
                    .map_err(|e| crypto_err(format!("invalid seed: {e:?}")))?,
            ),
            CRYPTO_ED25519 => KeypairInner::Ed25519(
                WipingEd25519Pair::from_seed_slice(seed)
                    .map_err(|e| crypto_err(format!("invalid seed: {e:?}")))?
                    .into_secret(),
            ),
            other => return Err(crypto_err(format!("unknown crypto type {other}"))),
        };
        Ok(Self {
            inner,
            ss58_format: DEFAULT_SS58_FORMAT,
            mnemonic: None,
            seed: Some(Zeroizing::new(seed.to_vec())),
        })
    }

    /// Derive a keypair from a secret URI (e.g. "//Alice" or "<mnemonic>//hard/soft").
    pub fn from_uri(uri: &str, crypto_type: u8) -> Result<Self, CoreError> {
        let inner = match crypto_type {
            CRYPTO_SR25519 => KeypairInner::Sr25519(
                sr25519::Pair::from_string(uri, None)
                    .map_err(|e| crypto_err(format!("invalid secret uri: {e:?}")))?,
            ),
            CRYPTO_ED25519 => KeypairInner::Ed25519(
                WipingEd25519Pair::from_string(uri, None)
                    .map_err(|e| crypto_err(format!("invalid secret uri: {e:?}")))?
                    .into_secret(),
            ),
            other => return Err(crypto_err(format!("unknown crypto type {other}"))),
        };
        // A URI may carry derivation junctions, so neither the phrase nor a
        // bare seed is retained.
        Ok(Self {
            inner,
            ss58_format: DEFAULT_SS58_FORMAT,
            mnemonic: None,
            seed: None,
        })
    }

    /// Derive a keypair from a hex-encoded private key or seed bytes.
    pub fn from_private_key(private_key: &str, crypto_type: u8) -> Result<Self, CoreError> {
        // Don't interpolate the hex error: it echoes offending secret characters.
        let private_key_vec = Zeroizing::new(
            hex::decode(private_key.trim_start_matches("0x"))
                .map_err(|_| crypto_err("invalid private_key hex string"))?,
        );

        let inner = match crypto_type {
            CRYPTO_SR25519 => {
                KeypairInner::Sr25519(sr25519::Pair::from_seed_slice(&private_key_vec).map_err(
                    |error| crypto_err(format!("invalid sr25519 private key: {error:?}")),
                )?)
            }
            CRYPTO_ED25519 => {
                let seed = if private_key_vec.len() >= 32 {
                    &private_key_vec[..32]
                } else {
                    return Err(crypto_err("ed25519 private key must be at least 32 bytes"));
                };
                KeypairInner::Ed25519(
                    WipingEd25519Pair::from_seed_slice(seed)
                        .map_err(|error| {
                            crypto_err(format!("invalid ed25519 private key: {error:?}"))
                        })?
                        .into_secret(),
                )
            }
            other => return Err(crypto_err(format!("unknown crypto type {other}"))),
        };

        Ok(Self {
            inner,
            ss58_format: DEFAULT_SS58_FORMAT,
            mnemonic: None,
            seed: None,
        })
    }

    /// Generate a fresh mnemonic with ``n_words`` (12/15/18/21/24).
    pub fn generate_mnemonic(n_words: usize) -> Result<String, CoreError> {
        use bip39::{Language, Mnemonic};

        if !matches!(n_words, 12 | 15 | 18 | 21 | 24) {
            return Err(crypto_err(format!(
                "unsupported mnemonic length {n_words}; expected 12, 15, 18, 21, or 24"
            )));
        }

        Mnemonic::generate_in(Language::English, n_words)
            .map(|mnemonic| mnemonic.to_string())
            .map_err(|error| crypto_err(format!("failed to generate mnemonic: {error}")))
    }

    /// Import a keypair from a PolkadotJS encrypted JSON keystore (v3).
    #[cfg(feature = "host")]
    pub fn from_encrypted_json(json_data: &str, passphrase: &str) -> Result<Self, CoreError> {
        encrypted_json::create_from_encrypted_json(json_data, passphrase)
    }

    pub fn crypto_type(&self) -> u8 {
        match &self.inner {
            KeypairInner::Ed25519(_) => CRYPTO_ED25519,
            KeypairInner::Sr25519(_) => CRYPTO_SR25519,
            KeypairInner::PublicOnly { crypto_type, .. } => *crypto_type,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        match &self.inner {
            KeypairInner::Ed25519(pair) => ed25519_public(pair),
            KeypairInner::Sr25519(pair) => pair.public().0,
            KeypairInner::PublicOnly { public_key, .. } => *public_key,
        }
    }

    pub fn ss58_address(&self) -> String {
        ss58_from_public(self.public_key_bytes(), self.ss58_format)
    }

    pub fn ss58_format(&self) -> u16 {
        self.ss58_format
    }

    pub fn private_key_bytes(&self) -> Option<Vec<u8>> {
        self.inner.private_key_bytes()
    }

    /// The BIP39 phrase this keypair was derived from, when retained.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref().map(String::as_str)
    }

    /// The raw seed this keypair was derived from, when retained.
    pub fn seed_bytes(&self) -> Option<&[u8]> {
        self.seed.as_deref().map(Vec::as_slice)
    }

    #[cfg(feature = "host")]
    pub(crate) fn from_inner(inner: KeypairInner, ss58_format: u16) -> Self {
        Self {
            inner,
            ss58_format,
            mnemonic: None,
            seed: None,
        }
    }

    /// Sign a message; returns the raw 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        match &self.inner {
            KeypairInner::Ed25519(pair) => Ok(pair.sign(message).to_bytes().to_vec()),
            KeypairInner::Sr25519(pair) => Ok(as_bytes(&pair.sign(message))),
            KeypairInner::PublicOnly { .. } => {
                Err(crypto_err("no private key set to create signatures"))
            }
        }
    }

    /// Verify a signature. Matches btwallet's ``<Bytes>`` wrapping fallback.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CoreError> {
        let public_key = self.public_key_bytes();
        let crypto_type = self.crypto_type();
        if verify_with_crypto(crypto_type, &public_key, message, signature)? {
            return Ok(true);
        }
        let wrapped = [b"<Bytes>", message, b"</Bytes>"].concat();
        verify_with_crypto(crypto_type, &public_key, &wrapped, signature)
    }

    /// Encrypt a message to this keypair's ed25519 public key (sealed box).
    #[cfg(feature = "host")]
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.crypto_type() != CRYPTO_ED25519 {
            return Err(crypto_err(
                "encrypt/decrypt is only supported for ed25519 keypairs",
            ));
        }
        ensure_sodium()?;
        let x25519_pk = ed25519_to_x25519_pk(&self.public_key_bytes())?;
        Ok(sealedbox::seal(message, &x25519_pk))
    }

    /// Decrypt a sealed-box ciphertext with this ed25519 keypair's private key.
    #[cfg(feature = "host")]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.crypto_type() != CRYPTO_ED25519 {
            return Err(crypto_err(
                "encrypt/decrypt is only supported for ed25519 keypairs",
            ));
        }
        let KeypairInner::Ed25519(pair) = &self.inner else {
            return Err(crypto_err(
                "decryption requires a keypair with a private key",
            ));
        };
        ensure_sodium()?;
        let (x25519_pk, x25519_sk) = ed25519_x25519_from_pair(pair)?;
        sealedbox::open(ciphertext, &x25519_pk, &x25519_sk)
            .map_err(|_| crypto_err("decryption failed: invalid ciphertext or wrong key"))
    }

    /// Encrypt a message for a recipient SS58 address (ed25519 sealed box).
    #[cfg(feature = "host")]
    pub fn encrypt_for(
        ss58_address: &str,
        message: &[u8],
        crypto_type: u8,
    ) -> Result<Vec<u8>, CoreError> {
        let recipient = Self::new(Some(ss58_address), None, crypto_type, DEFAULT_SS58_FORMAT)?;
        recipient.encrypt(message)
    }
}

/// Verify a signature against an SS58 address without holding the secret key.
pub fn verify(
    message: &[u8],
    signature: &[u8],
    ss58_address: &str,
    crypto_type: u8,
) -> Result<bool, CoreError> {
    let public_key = public_key_from_ss58(ss58_address)?;
    if verify_with_crypto(crypto_type, &public_key, message, signature)? {
        return Ok(true);
    }
    let wrapped = [b"<Bytes>", message, b"</Bytes>"].concat();
    verify_with_crypto(crypto_type, &public_key, &wrapped, signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sp_core::crypto::Ss58AddressFormat;

    use super::*;

    #[test]
    fn ss58_rendering_matches_sp_core() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for format in [0u16, 2, 42, 63, 64, 255, 4096, 16383] {
            for i in 0..50u32 {
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&i.to_le_bytes());
                for b in &mut key[4..] {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (state >> 33) as u8;
                }
                assert_eq!(
                    ss58_from_public(key, format),
                    AccountId32::from(key)
                        .to_ss58check_with_version(Ss58AddressFormat::custom(format)),
                    "diverged for format {format}"
                );
            }
        }
    }

    #[test]
    fn alice_uri_matches_known_address() {
        let kp = Keypair::from_uri("//Alice", CRYPTO_SR25519).unwrap();
        assert_eq!(
            kp.ss58_address(),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
    }

    #[test]
    fn public_only_from_ss58_matches_full_key() {
        let full = Keypair::from_uri("//Alice", CRYPTO_SR25519).unwrap();
        let public = Keypair::new(Some(&full.ss58_address()), None, CRYPTO_SR25519, 42).unwrap();
        assert_eq!(public.ss58_address(), full.ss58_address());
        assert_eq!(public.public_key_bytes(), full.public_key_bytes());
    }

    #[test]
    fn sr25519_verify_roundtrip() {
        let kp = Keypair::from_uri("//Alice", CRYPTO_SR25519).unwrap();
        let message = b"hello";
        let sig = kp.sign(message).unwrap();
        assert!(kp.verify(message, &sig).unwrap());
    }

    #[test]
    fn sr25519_verify_bytes_wrapping() {
        let kp = Keypair::from_uri("//Alice", CRYPTO_SR25519).unwrap();
        let sig = kp.sign(b"<Bytes>hello</Bytes>").unwrap();
        assert!(kp.verify(b"hello", &sig).unwrap());
    }

    #[test]
    fn ed25519_signing_object_has_a_wiping_owner_and_keeps_chain_bytes() {
        assert!(std::mem::needs_drop::<Zeroizing<SigningKey>>());
        assert!(std::mem::needs_drop::<Keypair>());

        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let keypair = Keypair::from_seed(&seed, CRYPTO_ED25519).unwrap();
        assert_eq!(
            hex::encode(keypair.public_key_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(keypair.sign(b"").unwrap()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }
}
