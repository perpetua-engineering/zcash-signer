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
use reddsa::{SigningKey, VerificationKey};

/// Zcash mainnet coin type (BIP-44 / ZIP-32)
pub const ZCASH_MAINNET_COIN_TYPE: u32 = 133;

/// PRF^expand personalization
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// Domain separator for Orchard ask derivation
const ORCHARD_ASK: u8 = 0x06;

/// Domain separator for Sapling ask derivation
const SAPLING_ASK: u8 = 0x00;
const SAPLING_NSK: u8 = 0x01;
const SAPLING_OVK: u8 = 0x02;
const SAPLING_DK: u8 = 0x10;

/// Domain separators for Sapling child derivation (ZIP-32)
const SAPLING_ZIP32_CHILD_HARDENED: u8 = 0x11;
const SAPLING_ZIP32_CHILD_ASK: u8 = 0x13;
const SAPLING_ZIP32_CHILD_NSK: u8 = 0x14;
const SAPLING_ZIP32_CHILD_OVK: u8 = 0x15;
const SAPLING_ZIP32_CHILD_DK: u8 = 0x16;

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

// -----------------------------------------------------------------------------
// Sapling Extended Key (proper ZIP-32 CKDh with additive derivation)
// -----------------------------------------------------------------------------

/// Sapling extended key carrying expanded components through child derivation.
///
/// Unlike Orchard (which replaces the 32-byte sk at each CKDh step), Sapling CKDh
/// operates on expanded key components (ask, nsk, ovk) additively. This struct
/// carries the full state needed for proper ZIP-32 Sapling child derivation.
pub(crate) struct SaplingExtendedKey {
    pub ask: JubjubScalar,
    pub nsk: JubjubScalar,
    pub ovk: [u8; 32],
    pub dk: [u8; 32],
    pub chain_code: [u8; 32],
}

impl SaplingExtendedKey {
    /// Derive the Sapling master extended key from a BIP-39 seed.
    pub fn master(seed: &[u8]) -> Self {
        let i = blake2b_personal(b"ZcashIP32Sapling", seed);
        let sk_m: [u8; 32] = i[..32].try_into().unwrap();
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..64]);

        // Expand sk_m to (ask, nsk, ovk) per ZIP-32
        let ask = JubjubScalar::from_bytes_wide(&prf_expand(&sk_m, SAPLING_ASK));
        let nsk = JubjubScalar::from_bytes_wide(&prf_expand(&sk_m, SAPLING_NSK));
        let ovk_exp = prf_expand(&sk_m, SAPLING_OVK);
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&ovk_exp[..32]);
        let dk_exp = prf_expand(&sk_m, SAPLING_DK); // master DK
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&dk_exp[..32]);

        SaplingExtendedKey { ask, nsk, ovk, dk, chain_code }
    }

    /// Derive a hardened child key using ZIP-32 Sapling CKDh.
    ///
    /// This implements the additive derivation specified in ZIP-32:
    /// - I = PRF^expand(c_par, 0x11 || expsk_bytes(96) || dk(32) || index_le(4))
    /// - child_ask = parent_ask + from_bytes_wide(PRF^expand(I_L, 0x13))
    /// - child_nsk = parent_nsk + from_bytes_wide(PRF^expand(I_L, 0x14))
    /// - child_ovk = truncate_32(PRF^expand(I_L, 0x15, parent_ovk))
    /// - child_dk  = truncate_32(PRF^expand(I_L, 0x16, parent_dk))
    pub fn derive_child(&self, index: u32) -> SaplingExtendedKey {
        let index_le = index.to_le_bytes();

        // Encode expanded spending key as 96 bytes: ask(32) || nsk(32) || ovk(32)
        let mut expsk_bytes = [0u8; 96];
        expsk_bytes[..32].copy_from_slice(&self.ask.to_bytes());
        expsk_bytes[32..64].copy_from_slice(&self.nsk.to_bytes());
        expsk_bytes[64..96].copy_from_slice(&self.ovk);

        // I = PRF^expand(c_par, 0x11 || expsk(96) || dk(32) || i_le(4))
        let tmp = {
            let h = Params::new()
                .hash_length(64)
                .personal(PRF_EXPAND_PERSONALIZATION)
                .to_state()
                .update(&self.chain_code)
                .update(&[SAPLING_ZIP32_CHILD_HARDENED])
                .update(&expsk_bytes)
                .update(&self.dk)
                .update(&index_le)
                .finalize();
            let mut out = [0u8; 64];
            out.copy_from_slice(h.as_bytes());
            out
        };

        let i_l: [u8; 32] = tmp[..32].try_into().unwrap();
        let mut c_i = [0u8; 32];
        c_i.copy_from_slice(&tmp[32..]);

        // child_ask = parent_ask + from_bytes_wide(PRF^expand(i_l, 0x13))
        let child_ask = self.ask + JubjubScalar::from_bytes_wide(&prf_expand(&i_l, SAPLING_ZIP32_CHILD_ASK));

        // child_nsk = parent_nsk + from_bytes_wide(PRF^expand(i_l, 0x14))
        let child_nsk = self.nsk + JubjubScalar::from_bytes_wide(&prf_expand(&i_l, SAPLING_ZIP32_CHILD_NSK));

        // child_ovk = truncate_32(PRF^expand(i_l, 0x15 || parent_ovk))
        let child_ovk = {
            let h = Params::new()
                .hash_length(64)
                .personal(PRF_EXPAND_PERSONALIZATION)
                .to_state()
                .update(&i_l)
                .update(&[SAPLING_ZIP32_CHILD_OVK])
                .update(&self.ovk)
                .finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.as_bytes()[..32]);
            out
        };

        // child_dk = truncate_32(PRF^expand(i_l, 0x16 || parent_dk))
        let child_dk = {
            let h = Params::new()
                .hash_length(64)
                .personal(PRF_EXPAND_PERSONALIZATION)
                .to_state()
                .update(&i_l)
                .update(&[SAPLING_ZIP32_CHILD_DK])
                .update(&self.dk)
                .finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.as_bytes()[..32]);
            out
        };

        SaplingExtendedKey {
            ask: child_ask,
            nsk: child_nsk,
            ovk: child_ovk,
            dk: child_dk,
            chain_code: c_i,
        }
    }

    /// Derive the extended key at ZIP-32 path m/32'/coin_type'/account'.
    pub fn from_seed_at_path(seed: &[u8], coin_type: u32, account: u32) -> Self {
        let master = Self::master(seed);
        let child_32 = master.derive_child(32 | 0x80000000);
        let child_coin = child_32.derive_child(coin_type | 0x80000000);
        child_coin.derive_child(account | 0x80000000)
    }

    /// Get the raw ask bytes (no sign normalization — matches upstream sapling-crypto).
    ///
    /// Sign normalization for RedJubjub is applied at signing time, not during
    /// key derivation.
    pub fn ask_bytes(&self) -> [u8; 32] {
        self.ask.to_bytes()
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

// -----------------------------------------------------------------------------
// pub(crate) Helper Functions (used by secure_sign)
// -----------------------------------------------------------------------------

/// Derive the 32-byte Orchard spending key from a BIP-39 seed.
///
/// Path: m/32'/coin_type'/account'
pub(crate) fn derive_orchard_sk(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let master = blake2b_personal(b"ZcashIP32Orchard", seed);

    let mut sk = [0u8; 32];
    let mut chain_code = [0u8; 32];
    sk.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..64]);

    derive_orchard_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, account | 0x80000000);

    sk
}

/// Derive the 32-byte Orchard ask from a spending key.
///
/// ask = PRF^expand(sk, 0x06) reduced to a normalized Pallas scalar.
pub(crate) fn derive_orchard_ask_bytes(sk: &[u8; 32]) -> [u8; 32] {
    let ask_expanded = prf_expand(sk, ORCHARD_ASK);
    let ask = normalize_orchard_ask(to_pallas_scalar(&ask_expanded));
    ask.to_repr()
}

/// Derive the 32-byte Sapling ask directly from a BIP-39 seed.
///
/// Uses proper ZIP-32 Sapling CKDh with additive derivation on expanded key components.
/// Path: m/32'/coin_type'/account'
pub(crate) fn derive_sapling_ask_bytes(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let ext = SaplingExtendedKey::from_seed_at_path(seed, coin_type, account);
    ext.ask_bytes()
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

/// Derive a Sapling extended spending key from a BIP-39 seed using ZIP-32
///
/// Path: m/32'/coin_type'/account'
///
/// Note: Sapling's ZIP-32 CKDh uses additive derivation on expanded key components
/// (ask, nsk, ovk). There is no single 32-byte "spending key" at child levels.
/// This function returns the normalized ask bytes (the spend authorization key),
/// which is the component needed for signing.
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

    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let ext = SaplingExtendedKey::from_seed_at_path(seed_slice, coin_type, account);

    // Return the normalized ask bytes (the spend authorization key)
    (*key_out).bytes = ext.ask_bytes();

    ZsigError::Success
}

/// Get the Sapling spend authorization key (ask) from a "spending key".
///
/// Since zsig_derive_sapling_spending_key now returns the ask bytes directly
/// (because Sapling's ZIP-32 CKDh doesn't have a raw spending key at child levels),
/// this function is effectively a copy for backward compatibility.
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

    // The "spending key" bytes are already the normalized ask from
    // zsig_derive_sapling_spending_key.
    (*ask_out).bytes = (*spending_key).bytes;

    ZsigError::Success
}

/// Convenience function: derive Sapling ask directly from seed
///
/// Uses proper ZIP-32 Sapling CKDh with additive derivation.
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

    if seed_len < 32 || seed_len > 252 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let ext = SaplingExtendedKey::from_seed_at_path(seed_slice, coin_type, account);

    (*ask_out).bytes = ext.ask_bytes();

    ZsigError::Success
}
