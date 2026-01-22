//! BIP-44 transparent address derivation
//!
//! Implements BIP-32/BIP-44 key derivation for Zcash transparent addresses.
//! Path: m/44'/133'/account'/0/index

use core::slice;
use crate::ZsigError;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{Scalar, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use ff::PrimeField;

type HmacSha512 = Hmac<Sha512>;

/// Zcash mainnet transparent address prefix (t1)
const MAINNET_P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];
/// Zcash testnet transparent address prefix (tm)
const TESTNET_P2PKH_PREFIX: [u8; 2] = [0x1D, 0x25];

// -----------------------------------------------------------------------------
// BIP-32 Helper Functions
// -----------------------------------------------------------------------------

/// Derive BIP-32 master key from seed
fn bip32_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..64]);
    (sk, chain_code)
}

/// Derive secp256k1 public key (compressed, 33 bytes)
fn derive_secp256k1_pubkey(sk: &[u8; 32]) -> Option<[u8; 33]> {
    let secret_key = SecretKey::from_slice(sk).ok()?;
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(true); // compressed
    let bytes = point.as_bytes();

    if bytes.len() != 33 {
        return None;
    }

    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    Some(result)
}

/// BIP-32 hardened child derivation
/// index should already have the hardened bit set (0x80000000)
fn bip32_derive_hardened(
    parent_sk: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Option<([u8; 32], [u8; 32])> {
    // For hardened derivation: HMAC-SHA512(chain_code, 0x00 || parent_sk || index)
    let mut mac = HmacSha512::new_from_slice(parent_chain_code).ok()?;
    mac.update(&[0x00]);
    mac.update(parent_sk);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Parse left 32 bytes as scalar and add to parent key
    let il: [u8; 32] = result[..32].try_into().ok()?;

    // Convert to scalars and add
    let parent_scalar = Scalar::from_repr((*parent_sk).into());
    if parent_scalar.is_none().into() {
        return None;
    }
    let il_scalar = Scalar::from_repr(il.into());
    if il_scalar.is_none().into() {
        return None;
    }

    let child_scalar = parent_scalar.unwrap() + il_scalar.unwrap();
    if child_scalar.is_zero().into() {
        return None; // Invalid key
    }

    let mut child_sk = [0u8; 32];
    child_sk.copy_from_slice(&child_scalar.to_bytes());

    let mut child_chain_code = [0u8; 32];
    child_chain_code.copy_from_slice(&result[32..64]);

    Some((child_sk, child_chain_code))
}

/// BIP-32 non-hardened child derivation
fn bip32_derive_normal(
    parent_sk: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Option<([u8; 32], [u8; 32])> {
    // Ensure index is non-hardened (< 0x80000000)
    if index >= 0x80000000 {
        return None;
    }

    // Get the public key from the parent secret key
    let parent_pubkey = derive_secp256k1_pubkey(parent_sk)?;

    // For non-hardened derivation: HMAC-SHA512(chain_code, pubkey || index)
    let mut mac = HmacSha512::new_from_slice(parent_chain_code).ok()?;
    mac.update(&parent_pubkey);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Parse left 32 bytes as scalar and add to parent key
    let il: [u8; 32] = result[..32].try_into().ok()?;

    // Convert to scalars and add
    let parent_scalar = Scalar::from_repr((*parent_sk).into());
    if parent_scalar.is_none().into() {
        return None;
    }
    let il_scalar = Scalar::from_repr(il.into());
    if il_scalar.is_none().into() {
        return None;
    }

    let child_scalar = parent_scalar.unwrap() + il_scalar.unwrap();
    if child_scalar.is_zero().into() {
        return None; // Invalid key
    }

    let mut child_sk = [0u8; 32];
    child_sk.copy_from_slice(&child_scalar.to_bytes());

    let mut child_chain_code = [0u8; 32];
    child_chain_code.copy_from_slice(&result[32..64]);

    Some((child_sk, child_chain_code))
}

/// Compute RIPEMD160(SHA256(data)) - P2PKH pubkey hash
fn pubkey_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;

    let sha_hash = Sha256::digest(pubkey);
    let mut ripe_hasher = Ripemd160::new();
    Digest::update(&mut ripe_hasher, &sha_hash);
    let result = ripe_hasher.finalize();

    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&result);
    hash160
}

/// Encode transparent P2PKH address as base58check string
fn encode_transparent_address(hash160: &[u8; 20], mainnet: bool) -> Vec<u8> {
    use sha2::{Sha256, Digest as Sha256Digest};

    // Address prefix: t1 for mainnet, tm for testnet
    let prefix: [u8; 2] = if mainnet {
        MAINNET_P2PKH_PREFIX
    } else {
        TESTNET_P2PKH_PREFIX
    };

    // Build payload: prefix || hash160
    let mut payload = [0u8; 22];
    payload[0..2].copy_from_slice(&prefix);
    payload[2..22].copy_from_slice(hash160);

    // Double SHA256 for checksum
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];

    // Build final data: payload || checksum
    let mut data = [0u8; 26];
    data[0..22].copy_from_slice(&payload);
    data[22..26].copy_from_slice(checksum);

    // Base58 encode
    bs58::encode(&data).into_vec()
}

// -----------------------------------------------------------------------------
// FFI Functions
// -----------------------------------------------------------------------------

/// Derive a transparent P2PKH address from seed using BIP-44
///
/// Path: m/44'/133'/account'/0/index
///
/// Returns the length of the address string (excluding null terminator),
/// or 0 on error.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 36 bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_transparent_address(
    seed: *const u8,
    seed_len: usize,
    account: u32,
    index: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if seed.is_null() || output.is_null() || output_len < 36 {
        return 0;
    }

    if seed_len < 16 || seed_len > 64 {
        return 0;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // Derive to m/44'/133'/account'/0/index using BIP-32
    let (mut sk, mut cc) = bip32_master_key(seed_slice);

    // m/44'
    match bip32_derive_hardened(&sk, &cc, 44 | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return 0,
    }

    // m/44'/133'
    match bip32_derive_hardened(&sk, &cc, 133 | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return 0,
    }

    // m/44'/133'/account'
    match bip32_derive_hardened(&sk, &cc, account | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return 0,
    }

    // m/44'/133'/account'/0 (external chain, non-hardened)
    match bip32_derive_normal(&sk, &cc, 0) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return 0,
    }

    // m/44'/133'/account'/0/index (address, non-hardened)
    match bip32_derive_normal(&sk, &cc, index) {
        Some((new_sk, _)) => { sk = new_sk; }
        None => return 0,
    }

    // Derive public key
    let pubkey = match derive_secp256k1_pubkey(&sk) {
        Some(pk) => pk,
        None => return 0,
    };

    // Hash pubkey: RIPEMD160(SHA256(pubkey))
    let hash160 = pubkey_hash160(&pubkey);

    // Encode as base58check t-address
    let addr_bytes = encode_transparent_address(&hash160, mainnet);

    // Write to output
    if addr_bytes.len() + 1 > output_len {
        return 0;
    }

    let out_slice = slice::from_raw_parts_mut(output, output_len);
    out_slice[..addr_bytes.len()].copy_from_slice(&addr_bytes);
    out_slice[addr_bytes.len()] = 0; // null terminate

    addr_bytes.len()
}

/// Derive transparent pubkey hash (20 bytes) from seed
///
/// This is useful for creating Unified Addresses with a transparent receiver.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `hash_out` must point to 20 writable bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_transparent_pubkey_hash(
    seed: *const u8,
    seed_len: usize,
    account: u32,
    index: u32,
    hash_out: *mut u8,
) -> ZsigError {
    if seed.is_null() || hash_out.is_null() {
        return ZsigError::NullPointer;
    }

    if seed_len < 16 || seed_len > 64 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // Derive to m/44'/133'/account'/0/index using BIP-32
    let (mut sk, mut cc) = bip32_master_key(seed_slice);

    // m/44'
    match bip32_derive_hardened(&sk, &cc, 44 | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return ZsigError::InvalidKey,
    }

    // m/44'/133'
    match bip32_derive_hardened(&sk, &cc, 133 | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return ZsigError::InvalidKey,
    }

    // m/44'/133'/account'
    match bip32_derive_hardened(&sk, &cc, account | 0x80000000) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return ZsigError::InvalidKey,
    }

    // m/44'/133'/account'/0 (external chain, non-hardened)
    match bip32_derive_normal(&sk, &cc, 0) {
        Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
        None => return ZsigError::InvalidKey,
    }

    // m/44'/133'/account'/0/index (address, non-hardened)
    match bip32_derive_normal(&sk, &cc, index) {
        Some((new_sk, _)) => { sk = new_sk; }
        None => return ZsigError::InvalidKey,
    }

    // Derive public key
    let pubkey = match derive_secp256k1_pubkey(&sk) {
        Some(pk) => pk,
        None => return ZsigError::InvalidKey,
    };

    // Hash pubkey: RIPEMD160(SHA256(pubkey))
    let hash160 = pubkey_hash160(&pubkey);

    // Copy to output
    let out_slice = slice::from_raw_parts_mut(hash_out, 20);
    out_slice.copy_from_slice(&hash160);

    ZsigError::Success
}

/// Sign a transparent input sighash using BIP-44 derived key
///
/// # Arguments
/// - `seed`: BIP-39 seed bytes
/// - `seed_len`: length of seed (usually 64)
/// - `derivation_path`: BIP-32 derivation path components
/// - `path_len`: number of path components (usually 5)
/// - `sighash`: 32-byte sighash to sign
/// - `sighash_type`: sighash type (usually 0x01 for SIGHASH_ALL)
/// - `signature_out`: output buffer for DER signature (at least 72 bytes)
/// - `signature_len_out`: output for actual signature length
/// - `pubkey_out`: output buffer for compressed pubkey (33 bytes)
///
/// # Safety
/// - All pointers must be valid
/// - signature_out must have space for 72 bytes
/// - pubkey_out must have space for 33 bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_transparent(
    seed: *const u8,
    seed_len: usize,
    derivation_path: *const u32,
    path_len: usize,
    sighash: *const u8,
    _sighash_type: u8,
    signature_out: *mut u8,
    signature_len_out: *mut usize,
    pubkey_out: *mut u8,
) -> ZsigError {
    if seed.is_null() || derivation_path.is_null() || sighash.is_null()
        || signature_out.is_null() || signature_len_out.is_null() || pubkey_out.is_null() {
        return ZsigError::NullPointer;
    }

    if seed_len < 16 || seed_len > 64 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let path_slice = slice::from_raw_parts(derivation_path, path_len);
    let sighash_slice = slice::from_raw_parts(sighash, 32);

    // Derive the key using the path
    let (mut sk, mut cc) = bip32_master_key(seed_slice);

    for &component in path_slice {
        let is_hardened = (component & 0x80000000) != 0;
        if is_hardened {
            match bip32_derive_hardened(&sk, &cc, component) {
                Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
                None => return ZsigError::InvalidKey,
            }
        } else {
            match bip32_derive_normal(&sk, &cc, component) {
                Some((new_sk, new_cc)) => { sk = new_sk; cc = new_cc; }
                None => return ZsigError::InvalidKey,
            }
        }
    }

    // Sign the sighash
    use k256::ecdsa::{SigningKey, signature::Signer};

    let signing_key = match SigningKey::from_slice(&sk) {
        Ok(key) => key,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Get the public key
    let pubkey = match derive_secp256k1_pubkey(&sk) {
        Some(pk) => pk,
        None => return ZsigError::InvalidKey,
    };

    // Sign - k256 produces a Signature
    let signature: k256::ecdsa::Signature = signing_key.sign(sighash_slice);

    // Convert to DER format
    let der_sig = signature.to_der();
    let der_bytes = der_sig.as_bytes();

    // Copy outputs
    let sig_out_slice = slice::from_raw_parts_mut(signature_out, der_bytes.len().min(72));
    sig_out_slice[..der_bytes.len().min(72)].copy_from_slice(&der_bytes[..der_bytes.len().min(72)]);
    *signature_len_out = der_bytes.len();

    let pubkey_out_slice = slice::from_raw_parts_mut(pubkey_out, 33);
    pubkey_out_slice.copy_from_slice(&pubkey);

    ZsigError::Success
}
