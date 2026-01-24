//! ZIP-32 key derivation for Orchard and Sapling
//!
//! Implements ZIP-32 key derivation for spending keys and ask for both protocols.

use core::slice;
use crate::{ZsigError, ZsigOrchardSpendingKey, ZsigOrchardAsk, ZsigSaplingSpendingKey, ZsigSaplingAsk};
use blake2b_simd::Params;
use ff::{PrimeField, FromUniformBytes};
use pasta_curves::pallas;
use jubjub::Fr as JubjubScalar;
use reddsa::orchard::SpendAuth as OrchardSpendAuth;
use reddsa::sapling::SpendAuth as SaplingSpendAuth;
use reddsa::{SigningKey, VerificationKey};

/// Zcash mainnet coin type (BIP-44 / ZIP-32)
pub const ZCASH_MAINNET_COIN_TYPE: u32 = 133;

/// PRF^expand personalization
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// Domain separator for Orchard ask derivation
const ORCHARD_ASK: u8 = 0x06;

/// Domain separator for Sapling ask derivation
const SAPLING_ASK: u8 = 0x00;

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

/// BLAKE2b-512 with personalization
fn blake2b_personal(personal: &[u8], data: &[u8]) -> [u8; 64] {
    let result = Params::new()
        .hash_length(64)
        .personal(personal)
        .hash(data);

    let mut output = [0u8; 64];
    output.copy_from_slice(result.as_bytes());
    output
}

/// PRF^expand: BLAKE2b-512 with "Zcash_ExpandSeed" personalization
fn prf_expand(sk: &[u8; 32], domain: u8) -> [u8; 64] {
    let result = Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(sk)
        .update(&[domain])
        .finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(result.as_bytes());
    out
}

/// Convert 64 bytes to Pallas scalar (mod r)
fn to_pallas_scalar(bytes: &[u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(bytes)
}

/// Convert 64 bytes to Jubjub scalar (mod r) for Sapling
fn to_jubjub_scalar(bytes: &[u8; 64]) -> JubjubScalar {
    JubjubScalar::from_bytes_wide(bytes)
}

/// Normalize Orchard ask to match Orchard's spend authorizing key derivation.
///
/// Orchard requires ask to be negated when the last bit of repr_P(ak) is 1.
fn normalize_orchard_ask(ask: pallas::Scalar) -> pallas::Scalar {
    let ask_bytes: [u8; 32] = ask.to_repr().into();
    let sk = match SigningKey::<OrchardSpendAuth>::try_from(ask_bytes) {
        Ok(key) => key,
        Err(_) => return ask,
    };

    let vk: VerificationKey<OrchardSpendAuth> = (&sk).into();
    let vk_bytes: [u8; 32] = vk.into();

    if (vk_bytes[31] >> 7) == 1 {
        -ask
    } else {
        ask
    }
}

/// Normalize Sapling ask to match Sapling's spend authorizing key derivation.
///
/// Sapling requires ask to be negated when the last bit of repr_J(ak) is 1.
fn normalize_sapling_ask(ask: JubjubScalar) -> JubjubScalar {
    let ask_bytes: [u8; 32] = ask.to_bytes();
    let sk = match SigningKey::<SaplingSpendAuth>::try_from(ask_bytes) {
        Ok(key) => key,
        Err(_) => return ask,
    };

    let vk: VerificationKey<SaplingSpendAuth> = (&sk).into();
    let vk_bytes: [u8; 32] = vk.into();

    if (vk_bytes[31] >> 7) == 1 {
        -ask
    } else {
        ask
    }
}

/// Derive a hardened Orchard child key using ZIP-32 CKDh
///
/// I = PRF^expand(c_par, 0x81 || sk_par || I2LEOSP_32(i))
fn derive_orchard_child(sk: &mut [u8; 32], chain_code: &mut [u8; 32], index: u32) {
    let index_le = index.to_le_bytes();

    // Build PRF^expand input: c_par || 0x81 || sk || i_le
    let mut input = [0u8; 32 + 1 + 32 + 4]; // 69 bytes
    input[..32].copy_from_slice(chain_code);
    input[32] = 0x81; // ORCHARD_ZIP32_CHILD domain separator
    input[33..65].copy_from_slice(sk);
    input[65..69].copy_from_slice(&index_le);

    let child = blake2b_personal(PRF_EXPAND_PERSONALIZATION, &input);
    sk.copy_from_slice(&child[..32]);
    chain_code.copy_from_slice(&child[32..64]);
}

/// Derive a hardened Sapling child key using ZIP-32 CKDh
///
/// I = PRF^expand(c_par, 0x11 || sk_par || I2LEOSP_32(i))
fn derive_sapling_child(sk: &mut [u8; 32], chain_code: &mut [u8; 32], index: u32) {
    let index_le = index.to_le_bytes();

    // Build PRF^expand input: c_par || 0x11 || sk || i_le
    let mut input = [0u8; 32 + 1 + 32 + 4]; // 69 bytes
    input[..32].copy_from_slice(chain_code);
    input[32] = 0x11; // SAPLING_ZIP32_CHILD domain separator
    input[33..65].copy_from_slice(sk);
    input[65..69].copy_from_slice(&index_le);

    let child = blake2b_personal(PRF_EXPAND_PERSONALIZATION, &input);
    sk.copy_from_slice(&child[..32]);
    chain_code.copy_from_slice(&child[32..64]);
}

// -----------------------------------------------------------------------------
// FFI Functions
// -----------------------------------------------------------------------------

/// Derive an Orchard spending key from a BIP-39 seed using ZIP-32
///
/// Path: m/32'/coin_type'/account'
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes (typically 64 bytes from BIP-39)
/// - `key_out` must point to valid memory for a ZsigOrchardSpendingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_spending_key(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    key_out: *mut ZsigOrchardSpendingKey,
) -> ZsigError {
    if seed.is_null() || key_out.is_null() {
        return ZsigError::NullPointer;
    }

    // ZIP-32 requires seed length between 32 and 252 bytes
    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // ZIP-32 Orchard master key derivation
    // I_master = BLAKE2b-512("ZcashIP32Orchard", seed)
    let master = blake2b_personal(b"ZcashIP32Orchard", seed_slice);

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..64]);

    // Hardened child derivation for path: m/32'/coin_type'/account'
    derive_orchard_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Return the spending key (sk), not ask yet
    (*key_out).bytes = sk;

    ZsigError::Success
}

/// Derive the spend authorization key (ask) from a spending key
///
/// ask = PRF^expand(sk, 0x06) reduced to a Pallas scalar
///
/// # Safety
/// - `spending_key` must point to a valid ZsigOrchardSpendingKey
/// - `ask_out` must point to valid memory for a ZsigOrchardAsk
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_ask(
    spending_key: *const ZsigOrchardSpendingKey,
    ask_out: *mut ZsigOrchardAsk,
) -> ZsigError {
    if spending_key.is_null() || ask_out.is_null() {
        return ZsigError::NullPointer;
    }

    let sk = (*spending_key).bytes;

    // ask = PRF^expand(sk, 0x06) reduced to scalar
    let ask_expanded = prf_expand(&sk, ORCHARD_ASK);
    let ask = normalize_orchard_ask(to_pallas_scalar(&ask_expanded));

    (*ask_out).bytes = ask.to_repr();

    ZsigError::Success
}

/// Convenience function: derive ask directly from seed
///
/// This combines zsig_derive_orchard_spending_key and zsig_derive_orchard_ask.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `ask_out` must point to valid memory for a ZsigOrchardAsk
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_ask_from_seed(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    ask_out: *mut ZsigOrchardAsk,
) -> ZsigError {
    if seed.is_null() || ask_out.is_null() {
        return ZsigError::NullPointer;
    }

    // ZIP-32 requires seed length between 32 and 252 bytes
    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // ZIP-32 Orchard master key derivation
    let master = blake2b_personal(b"ZcashIP32Orchard", seed_slice);

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..64]);

    // Hardened child derivation for path: m/32'/coin_type'/account'
    derive_orchard_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive ask from sk
    let ask_expanded = prf_expand(&sk, ORCHARD_ASK);
    let ask = normalize_orchard_ask(to_pallas_scalar(&ask_expanded));

    (*ask_out).bytes = ask.to_repr();

    ZsigError::Success
}

// -----------------------------------------------------------------------------
// Sapling FFI Functions
// -----------------------------------------------------------------------------

/// Derive a Sapling spending key from a BIP-39 seed using ZIP-32
///
/// Path: m/32'/coin_type'/account'
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes (typically 64 bytes from BIP-39)
/// - `key_out` must point to valid memory for a ZsigSaplingSpendingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_sapling_spending_key(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    key_out: *mut ZsigSaplingSpendingKey,
) -> ZsigError {
    if seed.is_null() || key_out.is_null() {
        return ZsigError::NullPointer;
    }

    // ZIP-32 requires seed length between 32 and 252 bytes
    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // ZIP-32 Sapling master key derivation
    // I_master = BLAKE2b-512("ZcashIP32Sapling", seed)
    let master = blake2b_personal(b"ZcashIP32Sapling", seed_slice);

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..64]);

    // Hardened child derivation for path: m/32'/coin_type'/account'
    derive_sapling_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Return the spending key (sk)
    (*key_out).bytes = sk;

    ZsigError::Success
}

/// Derive the Sapling spend authorization key (ask) from a spending key
///
/// ask = PRF^expand(sk, 0x00) reduced to a Jubjub scalar
///
/// # Safety
/// - `spending_key` must point to a valid ZsigSaplingSpendingKey
/// - `ask_out` must point to valid memory for a ZsigSaplingAsk
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_sapling_ask(
    spending_key: *const ZsigSaplingSpendingKey,
    ask_out: *mut ZsigSaplingAsk,
) -> ZsigError {
    if spending_key.is_null() || ask_out.is_null() {
        return ZsigError::NullPointer;
    }

    let sk = (*spending_key).bytes;

    // ask = PRF^expand(sk, 0x00) reduced to Jubjub scalar
    let ask_expanded = prf_expand(&sk, SAPLING_ASK);
    let ask = normalize_sapling_ask(to_jubjub_scalar(&ask_expanded));

    (*ask_out).bytes = ask.to_bytes();

    ZsigError::Success
}

/// Convenience function: derive Sapling ask directly from seed
///
/// This combines zsig_derive_sapling_spending_key and zsig_derive_sapling_ask.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `ask_out` must point to valid memory for a ZsigSaplingAsk
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_sapling_ask_from_seed(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    ask_out: *mut ZsigSaplingAsk,
) -> ZsigError {
    if seed.is_null() || ask_out.is_null() {
        return ZsigError::NullPointer;
    }

    // ZIP-32 requires seed length between 32 and 252 bytes
    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // ZIP-32 Sapling master key derivation
    let master = blake2b_personal(b"ZcashIP32Sapling", seed_slice);

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..64]);

    // Hardened child derivation for path: m/32'/coin_type'/account'
    derive_sapling_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive ask from sk
    let ask_expanded = prf_expand(&sk, SAPLING_ASK);
    let ask = normalize_sapling_ask(to_jubjub_scalar(&ask_expanded));

    (*ask_out).bytes = ask.to_bytes();

    ZsigError::Success
}
