//! Orchard address derivation and Unified Address encoding
//!
//! Implements:
//! - Orchard payment address derivation (ZIP-32)
//! - Unified Address encoding (ZIP-316)
//! - Unified Full Viewing Key (UFVK) derivation and encoding

use core::slice;
use crate::ZsigError;
use alloc::vec::Vec;
use alloc::string::String;
use blake2b_simd::Params;
use ff::{PrimeField, FromUniformBytes};
use pasta_curves::pallas;
use pasta_curves::arithmetic::CurveExt;
use group::GroupEncoding;
use sinsemilla::CommitDomain;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{Scalar, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use jubjub::{Fr as JubjubScalar, ExtendedPoint as JubjubPoint, AffinePoint as JubjubAffine};
use reddsa::sapling::SpendAuth as SaplingSpendAuth;

type HmacSha512 = Hmac<Sha512>;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// PRF^expand personalization
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// Domain separators for Orchard key derivation
const ORCHARD_ASK: u8 = 0x06;
const ORCHARD_NK: u8 = 0x07;
const ORCHARD_RIVK: u8 = 0x08;
const ORCHARD_DK_OVK: u8 = 0x82;

/// Domain separators for Sapling key derivation
const SAPLING_ASK: u8 = 0x00;
const SAPLING_NSK: u8 = 0x01;
const SAPLING_OVK: u8 = 0x02;

/// Sinsemilla domain for commit_ivk
const COMMIT_IVK_PERSONALIZATION: &str = "z.cash:Orchard-CommitIvk";

/// Hash-to-curve personalization for diversify_hash
const KEY_DIVERSIFICATION_PERSONALIZATION: &str = "z.cash:Orchard-gd";

/// Number of bits in an Orchard base field element
const L_ORCHARD_BASE: usize = 255;

/// Orchard SpendAuth basepoint: hash_to_curve("z.cash:Orchard")(b"G")
/// This is the generator used for ak = ask * B where B is this basepoint.
/// Different from pallas::Point::generator() which is the curve's standard generator.
const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];

// -----------------------------------------------------------------------------
// FFI Types
// -----------------------------------------------------------------------------

/// Orchard payment address (diversifier + pk_d)
#[repr(C)]
pub struct ZsigOrchardAddress {
    /// 11-byte diversifier
    pub diversifier: [u8; 11],
    /// 32-byte diversified transmission key (pk_d)
    pub pk_d: [u8; 32],
}

/// Orchard Full Viewing Key components
#[repr(C)]
pub struct ZsigOrchardFullViewingKey {
    /// 32-byte authorization key (ak)
    pub ak: [u8; 32],
    /// 32-byte nullifier deriving key (nk)
    pub nk: [u8; 32],
    /// 32-byte randomized ivk (rivk)
    pub rivk: [u8; 32],
}

/// Transparent Full Viewing Key (for combined UFVK)
/// Uses the ZIP-316 format: just chain_code (32) + pubkey (33) = 65 bytes
/// This matches what the SDK's AccountPubKey expects.
#[repr(C)]
pub struct ZsigTransparentFullViewingKey {
    /// 32-byte chain code
    pub chain_code: [u8; 32],
    /// 33-byte compressed public key
    pub pubkey: [u8; 33],
}

/// Sapling Full Viewing Key components
/// ZIP-316 format: ak (32) + nk (32) + ovk (32) + dk (32) = 128 bytes
#[repr(C)]
pub struct ZsigSaplingFullViewingKey {
    /// 32-byte authorization key (ak)
    pub ak: [u8; 32],
    /// 32-byte nullifier deriving key (nk)
    pub nk: [u8; 32],
    /// 32-byte outgoing viewing key (ovk)
    pub ovk: [u8; 32],
    /// 32-byte diversifier key (dk)
    pub dk: [u8; 32],
}

/// Combined Full Viewing Key (Transparent + Sapling + Orchard)
#[repr(C)]
pub struct ZsigCombinedFullViewingKey {
    pub transparent: ZsigTransparentFullViewingKey,
    pub sapling: ZsigSaplingFullViewingKey,
    pub orchard: ZsigOrchardFullViewingKey,
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

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

/// PRF^expand with additional data
fn prf_expand_with_data(key: &[u8; 32], domain: u8, data: &[u8]) -> [u8; 64] {
    let result = Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(key)
        .update(&[domain])
        .update(data)
        .finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(result.as_bytes());
    out
}

/// Convert 64 bytes to Pallas base field element (mod q)
fn to_base(bytes: &[u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(bytes)
}

/// Convert 64 bytes to Pallas scalar (mod r)
fn to_scalar(bytes: &[u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(bytes)
}

// -----------------------------------------------------------------------------
// BIP-32 Helper Functions (for Transparent FVK derivation)
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
    let parent_scalar_opt = Scalar::from_repr((*parent_sk).into());
    if parent_scalar_opt.is_none().into() {
        return None;
    }
    let parent_scalar = parent_scalar_opt.unwrap();

    let il_scalar_opt = Scalar::from_repr(il.into());
    if il_scalar_opt.is_none().into() {
        return None;
    }
    let il_scalar = il_scalar_opt.unwrap();

    let child_scalar = parent_scalar + il_scalar;
    if child_scalar.is_zero().into() {
        return None; // Invalid key
    }

    let mut child_sk = [0u8; 32];
    child_sk.copy_from_slice(&child_scalar.to_bytes());

    let mut child_chain_code = [0u8; 32];
    child_chain_code.copy_from_slice(&result[32..64]);

    Some((child_sk, child_chain_code))
}

/// F4Jumble - ZIP-316 address encoding scramble
fn f4_jumble(input: &[u8], output: &mut [u8]) -> bool {
    if input.len() != output.len() || input.len() < 48 || input.len() > 4194368 {
        return false;
    }

    let len = input.len();
    let left_len = core::cmp::min(64, len / 2);
    let right_len = len - left_len;

    let mut left = alloc::vec![0u8; left_len];
    let mut right = alloc::vec![0u8; right_len];
    left.copy_from_slice(&input[..left_len]);
    right.copy_from_slice(&input[left_len..]);

    // H personalization: "UA_F4Jumble_H" || round || 0 || 0
    let h_pers = |round: u8| -> [u8; 16] {
        let mut p = [0u8; 16];
        p[..13].copy_from_slice(b"UA_F4Jumble_H");
        p[13] = round;
        p
    };

    // G personalization: "UA_F4Jumble_G" || round || chunk_lo || chunk_hi
    let g_pers = |round: u8, chunk: u16| -> [u8; 16] {
        let mut p = [0u8; 16];
        p[..13].copy_from_slice(b"UA_F4Jumble_G");
        p[13] = round;
        p[14] = (chunk & 0xFF) as u8;
        p[15] = (chunk >> 8) as u8;
        p
    };

    // H function: hash RIGHT → XOR with LEFT
    let h_round = |left: &mut [u8], right: &[u8], round: u8| {
        let hash = Params::new()
            .hash_length(left.len())
            .personal(&h_pers(round))
            .hash(right);
        for (l, h) in left.iter_mut().zip(hash.as_bytes()) {
            *l ^= h;
        }
    };

    // G function: hash LEFT → XOR with RIGHT in 64-byte chunks
    let g_round = |left: &[u8], right: &mut [u8], round: u8| {
        let chunks = (right.len() + 63) / 64;
        for j in 0..chunks {
            let hash = Params::new()
                .hash_length(64)
                .personal(&g_pers(round, j as u16))
                .hash(left);
            let start = j * 64;
            let end = (start + 64).min(right.len());
            for (r, h) in right[start..end].iter_mut().zip(hash.as_bytes()) {
                *r ^= h;
            }
        }
    };

    // Apply F4Jumble: G(0), H(0), G(1), H(1)
    g_round(&left, &mut right, 0);
    h_round(&mut left, &right, 0);
    g_round(&left, &mut right, 1);
    h_round(&mut left, &right, 1);

    output[..left_len].copy_from_slice(&left);
    output[left_len..].copy_from_slice(&right);

    true
}

/// Simple Bech32m encoder
fn bech32_encode(hrp: &str, data: &[u8]) -> Option<String> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const BECH32M_CONST: u32 = 0x2bc830a3;

    fn polymod(values: &[u8]) -> u32 {
        const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk: u32 = 1;
        for v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
            for (i, g) in GEN.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut result = Vec::with_capacity(hrp.len() * 2 + 1);
        for c in hrp.chars() {
            result.push((c as u8) >> 5);
        }
        result.push(0);
        for c in hrp.chars() {
            result.push((c as u8) & 0x1f);
        }
        result
    }

    // Create checksum
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    let polymod_value = polymod(&values) ^ BECH32M_CONST;
    let checksum: [u8; 6] = [
        ((polymod_value >> 25) & 0x1f) as u8,
        ((polymod_value >> 20) & 0x1f) as u8,
        ((polymod_value >> 15) & 0x1f) as u8,
        ((polymod_value >> 10) & 0x1f) as u8,
        ((polymod_value >> 5) & 0x1f) as u8,
        (polymod_value & 0x1f) as u8,
    ];

    // Build result string
    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    result.push_str(hrp);
    result.push('1');

    for &d in data {
        if d >= 32 {
            return None;
        }
        result.push(CHARSET[d as usize] as char);
    }

    for &c in &checksum {
        result.push(CHARSET[c as usize] as char);
    }

    Some(result)
}

/// Convert bytes to 5-bit groups for Bech32 encoding
fn to_5bit_groups(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity((bytes.len() * 8 + 4) / 5);
    let mut acc = 0u32;
    let mut bits = 0;

    for byte in bytes {
        acc = (acc << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 0x1f) as u8);
        }
    }

    if bits > 0 {
        let remaining = acc & ((1u32 << bits) - 1);
        result.push(((remaining << (5 - bits)) & 0x1f) as u8);
    }

    result
}

// -----------------------------------------------------------------------------
// ZIP-32 Orchard Key Derivation Helpers
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

/// Derive a hardened Orchard child key using ZIP-32 CKDh
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

/// Convert 64 bytes to Jubjub scalar (mod r)
fn to_jubjub_scalar(bytes: &[u8; 64]) -> JubjubScalar {
    JubjubScalar::from_bytes_wide(bytes)
}

/// Sapling SpendAuth basepoint on Jubjub curve
/// This is SPENDING_KEY_GENERATOR from the Zcash protocol spec (group_hash("Zcash_G_", ""))
/// Extracted from reddsa crate constants.rs
const SAPLING_SPENDING_KEY_GENERATOR: [u8; 32] = [
    48, 181, 242, 170, 173, 50, 86, 48, 188, 221, 219, 206, 77, 103, 101, 109, 5, 253, 28, 194,
    208, 55, 187, 83, 117, 182, 233, 109, 158, 1, 161, 215,
];

/// Sapling Nullifier proving key basepoint (PROOF_GENERATION_KEY_GENERATOR)
/// This is H = group_hash("Zcash_H_", "") used for nk = nsk * H
///
/// Computed from sapling-crypto constants.rs y-coordinate:
/// [0x467a_f9f7_e05d_e8e7, 0x50df_51ea_f5a1_49d2, 0xdec9_0184_0f49_48cc, 0x54b6_d107_18df_2a7a]
/// The sign bit IS set since x LSB = 1.
const SAPLING_PROOF_GEN_KEY_GENERATOR: [u8; 32] = [
    0xe7, 0xe8, 0x5d, 0xe0, 0xf7, 0xf9, 0x7a, 0x46,
    0xd2, 0x49, 0xa1, 0xf5, 0xea, 0x51, 0xdf, 0x50,
    0xcc, 0x48, 0x49, 0x0f, 0x84, 0x01, 0xc9, 0xde,
    0x7a, 0x2a, 0xdf, 0x18, 0x07, 0xd1, 0xb6, 0xd4, // 0xd4 (sign bit set)
];

/// Get Sapling SpendAuth basepoint
fn sapling_spend_auth_basepoint() -> JubjubPoint {
    JubjubAffine::from_bytes(SAPLING_SPENDING_KEY_GENERATOR)
        .expect("Invalid Sapling spending key generator")
        .into()
}

/// Get Sapling Proof Generation Key basepoint (for nk derivation)
fn sapling_proof_gen_basepoint() -> JubjubPoint {
    JubjubAffine::from_bytes(SAPLING_PROOF_GEN_KEY_GENERATOR)
        .expect("Invalid Sapling proof generation key generator")
        .into()
}

// -----------------------------------------------------------------------------
// FFI Functions - Address Derivation
// -----------------------------------------------------------------------------

/// Derive Orchard address from spending key
///
/// This derives the full Orchard payment address from a spending key:
/// 1. sk → ask, nk, rivk (using PRF^expand)
/// 2. ask → ak (scalar multiplication)
/// 3. (ak, nk, rivk) → ivk (Sinsemilla commit)
/// 4. rivk || ak || nk → dk (PRF^expand)
/// 5. dk + index → diversifier (using default index 0)
/// 6. diversifier → g_d (hash to curve)
/// 7. ivk * g_d → pk_d
/// 8. (diversifier, pk_d) → address
///
/// # Safety
/// - `spending_key` must point to 32 readable bytes
/// - `address_out` must point to valid memory for a ZsigOrchardAddress
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_address(
    spending_key: *const u8,
    address_out: *mut ZsigOrchardAddress,
) -> ZsigError {
    if spending_key.is_null() || address_out.is_null() {
        return ZsigError::NullPointer;
    }

    let sk: [u8; 32] = slice::from_raw_parts(spending_key, 32).try_into().unwrap();

    // Step 1: Derive ask, nk, rivk from spending key
    let ask_expanded = prf_expand(&sk, ORCHARD_ASK);
    let ask = to_scalar(&ask_expanded);

    let nk_expanded = prf_expand(&sk, ORCHARD_NK);
    let nk = to_base(&nk_expanded);

    let rivk_expanded = prf_expand(&sk, ORCHARD_RIVK);
    let rivk = to_scalar(&rivk_expanded);

    // Step 2: Derive ak = ask * B (SpendAuth basepoint)
    let spendauth_basepoint_opt = pallas::Point::from_bytes(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES);
    if spendauth_basepoint_opt.is_none().into() {
        return ZsigError::InvalidKey;
    }
    let spendauth_basepoint: pallas::Point = spendauth_basepoint_opt.unwrap();
    let ak: pallas::Point = spendauth_basepoint * ask;
    let mut ak_bytes = ak.to_bytes();

    // Extract ak_x (x-coordinate) for Sinsemilla input
    // Clear sign bit to get raw x-coordinate
    ak_bytes[31] &= 0x7f;
    let ak_base_opt = pallas::Base::from_repr(ak_bytes);
    if ak_base_opt.is_none().into() {
        return ZsigError::InvalidKey;
    }
    let ak_base: pallas::Base = ak_base_opt.unwrap();

    // Step 3: Compute ivk using Sinsemilla commit
    // ivk = SinsemillaShortCommit("z.cash:Orchard-CommitIvk", ak || nk, rivk)
    let commit_domain = CommitDomain::new(COMMIT_IVK_PERSONALIZATION);

    // Create bit iterator for ak || nk (each truncated to L_ORCHARD_BASE bits)
    let ak_bits = ak_base.to_repr();
    let nk_bits = nk.to_repr();

    let msg_bits = ak_bits.iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .take(L_ORCHARD_BASE)
        .chain(
            nk_bits.iter()
                .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
                .take(L_ORCHARD_BASE)
        );

    let ivk_result = commit_domain.short_commit(msg_bits, &rivk);
    if ivk_result.is_none().into() {
        return ZsigError::SigningFailed; // Sinsemilla commit failed
    }
    let ivk_base: pallas::Base = ivk_result.unwrap();

    // Convert ivk from Base to Scalar for multiplication
    let ivk_repr = ivk_base.to_repr();
    let ivk_scalar_opt = pallas::Scalar::from_repr(ivk_repr);
    if ivk_scalar_opt.is_none().into() {
        return ZsigError::ScalarConversionFailed;
    }
    let ivk: pallas::Scalar = ivk_scalar_opt.unwrap();

    // Step 4: Derive dk (diversifier key) from rivk, ak, nk
    // dk = truncate_32(PRF^expand(rivk, [0x82] || ak || nk))
    let rivk_bytes: [u8; 32] = rivk.to_repr();
    let mut dk_input = [0u8; 64];
    dk_input[..32].copy_from_slice(&ak.to_bytes());
    dk_input[32..64].copy_from_slice(&nk.to_repr());

    let _dk_expanded = prf_expand_with_data(&rivk_bytes, ORCHARD_DK_OVK, &dk_input);
    // Note: dk is used for diversifier derivation with FF1-AES
    // For simplicity, we use the default diversifier (all zeros)

    // Step 5: Use default diversifier (index 0)
    let diversifier = [0u8; 11];

    // Step 6: Compute g_d = DiversifyHash(diversifier)
    let g_d = pallas::Point::hash_to_curve(KEY_DIVERSIFICATION_PERSONALIZATION)(&diversifier);

    // Step 7: Compute pk_d = ivk * g_d
    let pk_d = g_d * ivk;
    let pk_d_bytes = pk_d.to_bytes();

    // Step 8: Return the address
    (*address_out).diversifier = diversifier;
    (*address_out).pk_d = pk_d_bytes;

    ZsigError::Success
}

/// Derive Orchard address from seed using ZIP-32
///
/// Convenience function that derives the spending key first, then the address.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `address_out` must point to valid memory for a ZsigOrchardAddress
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_address_from_seed(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    address_out: *mut ZsigOrchardAddress,
) -> ZsigError {
    if seed.is_null() || address_out.is_null() {
        return ZsigError::NullPointer;
    }

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

    // Hardened child derivation: m/32'/coin_type'/account'
    derive_orchard_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive address from spending key
    zsig_derive_orchard_address(sk.as_ptr(), address_out)
}

// -----------------------------------------------------------------------------
// FFI Functions - Unified Address Encoding
// -----------------------------------------------------------------------------

/// Encode an Orchard address as a Unified Address string
///
/// Returns the length of the encoded string (excluding null terminator),
/// or 0 on error.
///
/// # Safety
/// - `address` must point to a valid ZsigOrchardAddress
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 256
#[no_mangle]
pub unsafe extern "C" fn zsig_encode_unified_address(
    address: *const ZsigOrchardAddress,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if address.is_null() || output.is_null() || output_len < 256 {
        return 0;
    }

    let addr = &*address;
    let hrp = if mainnet { "u" } else { "utest" };

    // Build TLV for Orchard receiver + HRP padding
    // TLV = [0x03] || [43] || diversifier (11) || pk_d (32)
    // Padding = HRP right-padded with zeros to 16 bytes
    // Total: 45 (TLV) + 16 (padding) = 61 bytes (minimum 48 for F4Jumble)
    let mut raw = [0u8; 61];
    raw[0] = 0x03; // Orchard receiver type
    raw[1] = 43;   // Length: 11 + 32
    raw[2..13].copy_from_slice(&addr.diversifier);
    raw[13..45].copy_from_slice(&addr.pk_d);

    // Append HRP right-padded with zeros to 16 bytes
    let hrp_bytes = hrp.as_bytes();
    raw[45..45 + hrp_bytes.len()].copy_from_slice(hrp_bytes);

    // Apply F4Jumble
    let mut jumbled = [0u8; 61];
    if !f4_jumble(&raw, &mut jumbled) {
        return 0;
    }

    // Convert to 5-bit groups for Bech32m
    let data_5bit = to_5bit_groups(&jumbled);

    // Encode as Bech32m
    let encoded = match bech32_encode(hrp, &data_5bit) {
        Some(s) => s,
        None => return 0,
    };

    let len = encoded.len();
    if len >= output_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(output, len + 1);
    output_slice[..len].copy_from_slice(encoded.as_bytes());
    output_slice[len] = 0; // Null terminator

    len
}

/// Encode a Unified Address with both Orchard and transparent P2PKH receivers
///
/// This creates a UA that CEXs can use: they'll send to the transparent receiver
/// if they don't support Orchard. Per ZIP-316, receivers are ordered by typecode
/// (P2PKH=0x00 first, Orchard=0x03 second).
///
/// # Safety
/// - `orchard_addr` must point to a valid ZsigOrchardAddress
/// - `transparent_pkh` must point to 20 readable bytes
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 256
#[no_mangle]
pub unsafe extern "C" fn zsig_encode_unified_address_with_transparent(
    orchard_addr: *const ZsigOrchardAddress,
    transparent_pkh: *const u8,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if orchard_addr.is_null() || transparent_pkh.is_null() || output.is_null() || output_len < 256 {
        return 0;
    }

    let orchard = &*orchard_addr;
    let transparent: [u8; 20] = slice::from_raw_parts(transparent_pkh, 20).try_into().unwrap();

    // TLV receivers ordered by typecode ascending:
    // P2PKH transparent: [0x00] || [20] || pubkey_hash (22 bytes)
    // Orchard:           [0x03] || [43] || diversifier (11) || pk_d (32) (45 bytes)
    // Total: 67 bytes
    let mut tlv = [0u8; 67];

    // P2PKH transparent receiver (typecode 0x00)
    tlv[0] = 0x00;
    tlv[1] = 20;
    tlv[2..22].copy_from_slice(&transparent);

    // Orchard receiver (typecode 0x03)
    tlv[22] = 0x03;
    tlv[23] = 43;
    tlv[24..35].copy_from_slice(&orchard.diversifier);
    tlv[35..67].copy_from_slice(&orchard.pk_d);

    // Apply F4Jumble
    let mut jumbled = [0u8; 67];
    if !f4_jumble(&tlv, &mut jumbled) {
        return 0;
    }

    // Encode as Bech32m
    let hrp = if mainnet { "u" } else { "utest" };
    let data_5bit = to_5bit_groups(&jumbled);

    let encoded = match bech32_encode(hrp, &data_5bit) {
        Some(s) => s,
        None => return 0,
    };

    let len = encoded.len();
    if len >= output_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(output, len + 1);
    output_slice[..len].copy_from_slice(encoded.as_bytes());
    output_slice[len] = 0;

    len
}

// -----------------------------------------------------------------------------
// FFI Functions - Full Viewing Key
// -----------------------------------------------------------------------------

/// Derive Orchard Full Viewing Key from seed
///
/// FVK consists of: ak (authorization key), nk (nullifier key), rivk (randomized ivk)
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `fvk_out` must point to valid memory for a ZsigOrchardFullViewingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_full_viewing_key(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    fvk_out: *mut ZsigOrchardFullViewingKey,
) -> ZsigError {
    if seed.is_null() || fvk_out.is_null() {
        return ZsigError::NullPointer;
    }

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

    // Hardened child derivation: m/32'/coin_type'/account'
    derive_orchard_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_orchard_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive FVK components
    let ask_expanded = prf_expand(&sk, ORCHARD_ASK);
    let mut ask = to_scalar(&ask_expanded);

    let nk_expanded = prf_expand(&sk, ORCHARD_NK);
    let nk = to_base(&nk_expanded);

    let rivk_expanded = prf_expand(&sk, ORCHARD_RIVK);
    let rivk = to_scalar(&rivk_expanded);

    // ak = ask * B (SpendAuth basepoint)
    let spendauth_basepoint_opt = pallas::Point::from_bytes(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES);
    if spendauth_basepoint_opt.is_none().into() {
        return ZsigError::InvalidKey;
    }
    let spendauth_basepoint: pallas::Point = spendauth_basepoint_opt.unwrap();

    // Per Zcash protocol spec, if the high bit of ak's y-coordinate is 1,
    // we must negate ask to ensure ak has canonical form with y_tilde = 0.
    let mut ak: pallas::Point = spendauth_basepoint * ask;
    let mut ak_bytes = ak.to_bytes();

    if (ak_bytes[31] >> 7) == 1 {
        ask = -ask;
        ak = spendauth_basepoint * ask;
        ak_bytes = ak.to_bytes();
    }

    // Store FVK components
    (*fvk_out).ak = ak_bytes;
    (*fvk_out).nk = nk.to_repr();
    (*fvk_out).rivk = rivk.to_repr();

    ZsigError::Success
}

/// Derive Sapling Full Viewing Key from seed
///
/// FVK consists of: ak (authorization key), nk (nullifier key), ovk (outgoing viewing key), dk (diversifier key)
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `fvk_out` must point to valid memory for a ZsigSaplingFullViewingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_sapling_full_viewing_key(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    fvk_out: *mut ZsigSaplingFullViewingKey,
) -> ZsigError {
    if seed.is_null() || fvk_out.is_null() {
        return ZsigError::NullPointer;
    }

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

    // Hardened child derivation: m/32'/coin_type'/account'
    derive_sapling_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive FVK components from spending key
    // ask = PRF^expand(sk, 0x00)
    let ask_expanded = prf_expand(&sk, SAPLING_ASK);
    let mut ask = to_jubjub_scalar(&ask_expanded);

    // nsk = PRF^expand(sk, 0x01)
    let nsk_expanded = prf_expand(&sk, SAPLING_NSK);
    let nsk = to_jubjub_scalar(&nsk_expanded);

    // ovk = truncate_32(PRF^expand(sk, 0x02))
    let ovk_expanded = prf_expand(&sk, SAPLING_OVK);
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&ovk_expanded[..32]);

    // dk (diversifier key) - derived from sk
    // dk = truncate_32(PRF^expand(sk, 0x10))
    let dk_expanded = prf_expand(&sk, 0x10);
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_expanded[..32]);

    // ak = ask * G (Sapling SpendAuth basepoint)
    // Use reddsa's SigningKey/VerificationKey which handles the basepoint correctly
    let ask_bytes: [u8; 32] = ask.to_bytes();
    let sk: reddsa::SigningKey<SaplingSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Get ak from verification key, with normalization
    let mut vk: reddsa::VerificationKey<SaplingSpendAuth> = (&sk).into();
    let mut ak_bytes: [u8; 32] = vk.into();

    // Normalize: if high bit of ak encoding is 1, negate ask and recompute
    if (ak_bytes[31] >> 7) == 1 {
        ask = -ask;
        let ask_bytes_neg: [u8; 32] = ask.to_bytes();
        let sk_neg: reddsa::SigningKey<SaplingSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes_neg) {
            Ok(k) => k,
            Err(_) => return ZsigError::InvalidKey,
        };
        vk = (&sk_neg).into();
        ak_bytes = vk.into();
    }

    // nk = nsk * H (proof generation basepoint)
    let proof_basepoint = sapling_proof_gen_basepoint();
    let nk: JubjubPoint = proof_basepoint * nsk;
    let nk_bytes = JubjubAffine::from(nk).to_bytes();

    // Store FVK components
    (*fvk_out).ak = ak_bytes;
    (*fvk_out).nk = nk_bytes;
    (*fvk_out).ovk = ovk;
    (*fvk_out).dk = dk;

    ZsigError::Success
}

/// Derive the first valid Sapling diversifier index from a BIP-39 seed
///
/// This function derives the Sapling diversifier key (dk) from the seed,
/// then searches for the first index where the diversifier produces a valid
/// Sapling address (DiversifyHash doesn't return ⊥).
///
/// The returned index should be used for:
/// - Sapling address derivation (diversifier index)
/// - Transparent address derivation (BIP-44 index)
///
/// This ensures the Unified Address will have matching diversifier indices
/// across all receiver types, as required by ZIP-316.
///
/// # Safety
/// - `seed` must point to `seed_len` readable bytes
/// - `seed_len` must be between 32 and 252
/// - `index_out` must point to a writable u64
/// - `diversifier_out` must point to 11 writable bytes (optional, can be null)
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_first_valid_diversifier_index(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    index_out: *mut u64,
    diversifier_out: *mut u8,
) -> ZsigError {
    use crate::diversifier::find_first_valid_diversifier;

    if seed.is_null() || index_out.is_null() {
        return ZsigError::NullPointer;
    }

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

    // Hardened child derivation: m/32'/coin_type'/account'
    derive_sapling_child(&mut sk, &mut chain_code, 32 | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, coin_type | 0x80000000);
    derive_sapling_child(&mut sk, &mut chain_code, account | 0x80000000);

    // Derive dk from sk
    // dk = truncate_32(PRF^expand(sk, 0x10))
    let dk_expanded = prf_expand(&sk, 0x10);
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_expanded[..32]);

    // Find first valid diversifier index
    let (index, diversifier) = find_first_valid_diversifier(&dk);

    *index_out = index;

    if !diversifier_out.is_null() {
        slice::from_raw_parts_mut(diversifier_out, 11).copy_from_slice(&diversifier);
    }

    ZsigError::Success
}

/// Encode an Orchard Full Viewing Key as a Unified Full Viewing Key string
///
/// Returns the length of the encoded string (excluding null terminator),
/// or 0 on error.
///
/// # Safety
/// - `fvk` must point to a valid ZsigOrchardFullViewingKey
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 512
#[no_mangle]
pub unsafe extern "C" fn zsig_encode_unified_full_viewing_key(
    fvk: *const ZsigOrchardFullViewingKey,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if fvk.is_null() || output.is_null() || output_len < 512 {
        return 0;
    }

    let fvk_ref = &*fvk;
    let hrp = if mainnet { "uview" } else { "uviewtest" };

    // UFVK format (ZIP-316):
    // TLV = [0x03] || [96] || ak (32) || nk (32) || rivk (32) = 98 bytes
    // Padding = HRP right-padded with zeros to 16 bytes
    // Total: 98 + 16 = 114 bytes
    let mut raw = [0u8; 114];
    raw[0] = 0x03; // Orchard FVK type
    raw[1] = 96;   // Length: 32 + 32 + 32
    raw[2..34].copy_from_slice(&fvk_ref.ak);
    raw[34..66].copy_from_slice(&fvk_ref.nk);
    raw[66..98].copy_from_slice(&fvk_ref.rivk);

    // Append HRP right-padded to 16 bytes
    let hrp_bytes = hrp.as_bytes();
    raw[98..98 + hrp_bytes.len()].copy_from_slice(hrp_bytes);

    // Apply F4Jumble
    let mut jumbled = [0u8; 114];
    if !f4_jumble(&raw, &mut jumbled) {
        return 0;
    }

    // Convert to 5-bit groups and encode as Bech32m
    let data_5bit = to_5bit_groups(&jumbled);

    let encoded = match bech32_encode(hrp, &data_5bit) {
        Some(s) => s,
        None => return 0,
    };

    let len = encoded.len();
    if len >= output_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(output, len + 1);
    output_slice[..len].copy_from_slice(encoded.as_bytes());
    output_slice[len] = 0;

    len
}

/// Derive UFVK string directly from seed (convenience function)
///
/// Returns the length of the encoded string (excluding null terminator),
/// or negative error code on failure.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 512
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_ufvk_string(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if seed.is_null() || output.is_null() || output_len < 512 {
        return -1;
    }

    let mut fvk = ZsigOrchardFullViewingKey {
        ak: [0u8; 32],
        nk: [0u8; 32],
        rivk: [0u8; 32],
    };

    let result = zsig_derive_orchard_full_viewing_key(
        seed,
        seed_len,
        coin_type,
        account,
        &mut fvk,
    );

    if result as i32 != 0 {
        return -(result as i32);
    }

    let len = zsig_encode_unified_full_viewing_key(&fvk, mainnet, output, output_len);

    if len == 0 {
        return -100; // Encoding failed
    }

    len as i32
}

// -----------------------------------------------------------------------------
// Combined UFVK (Orchard + Transparent)
// -----------------------------------------------------------------------------

/// Derive transparent Full Viewing Key from seed using BIP-44
/// Path: m/44'/133'/account'
///
/// Returns chain_code + pubkey for UFVK encoding (ZIP-316 format).
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes (typically 64 bytes from BIP-39)
/// - `fvk_out` must point to valid memory for a ZsigTransparentFullViewingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_transparent_full_viewing_key(
    seed: *const u8,
    seed_len: usize,
    account: u32,
    fvk_out: *mut ZsigTransparentFullViewingKey,
) -> ZsigError {
    if seed.is_null() || fvk_out.is_null() {
        return ZsigError::NullPointer;
    }

    if seed_len < 16 || seed_len > 64 {
        return ZsigError::InvalidSeed;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    // Step 1: Master key from seed
    let (mut sk, mut chain_code) = bip32_master_key(seed_slice);

    // Step 2: Derive m/44' (purpose)
    match bip32_derive_hardened(&sk, &chain_code, 44 | 0x80000000) {
        Some((new_sk, new_cc)) => {
            sk = new_sk;
            chain_code = new_cc;
        }
        None => return ZsigError::InvalidKey,
    }

    // Step 3: Derive m/44'/133' (coin type = Zcash)
    match bip32_derive_hardened(&sk, &chain_code, 133 | 0x80000000) {
        Some((new_sk, new_cc)) => {
            sk = new_sk;
            chain_code = new_cc;
        }
        None => return ZsigError::InvalidKey,
    }

    // Step 4: Derive m/44'/133'/account'
    match bip32_derive_hardened(&sk, &chain_code, account | 0x80000000) {
        Some((new_sk, new_cc)) => {
            sk = new_sk;
            chain_code = new_cc;
        }
        None => return ZsigError::InvalidKey,
    }

    // Get compressed public key at account level
    let pubkey = match derive_secp256k1_pubkey(&sk) {
        Some(pk) => pk,
        None => return ZsigError::InvalidKey,
    };

    // Write output - ZIP-316 format (just chain_code + pubkey)
    (*fvk_out).chain_code = chain_code;
    (*fvk_out).pubkey = pubkey;

    ZsigError::Success
}

/// Derive combined Full Viewing Key (Transparent + Sapling + Orchard) from seed
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `fvk_out` must point to valid memory for a ZsigCombinedFullViewingKey
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_combined_full_viewing_key(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    fvk_out: *mut ZsigCombinedFullViewingKey,
) -> ZsigError {
    if seed.is_null() || fvk_out.is_null() {
        return ZsigError::NullPointer;
    }

    // Derive Transparent FVK
    let transparent_result = zsig_derive_transparent_full_viewing_key(
        seed,
        seed_len,
        account,
        &mut (*fvk_out).transparent,
    );
    if transparent_result as i32 != 0 {
        return transparent_result;
    }

    // Derive Sapling FVK
    let sapling_result = zsig_derive_sapling_full_viewing_key(
        seed,
        seed_len,
        coin_type,
        account,
        &mut (*fvk_out).sapling,
    );
    if sapling_result as i32 != 0 {
        return sapling_result;
    }

    // Derive Orchard FVK
    let orchard_result = zsig_derive_orchard_full_viewing_key(
        seed,
        seed_len,
        coin_type,
        account,
        &mut (*fvk_out).orchard,
    );
    if orchard_result as i32 != 0 {
        return orchard_result;
    }

    ZsigError::Success
}

/// Encode a Combined Full Viewing Key as a Unified Full Viewing Key string
///
/// This creates a UFVK with transparent (P2PKH), Sapling, and Orchard receivers.
/// Per ZIP-316, receivers are ordered by typecode ascending.
///
/// Returns the length of the encoded string (excluding null terminator),
/// or 0 on error. The output buffer must be at least 512 bytes.
///
/// # Safety
/// - `fvk` must point to a valid ZsigCombinedFullViewingKey
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 512
#[no_mangle]
pub unsafe extern "C" fn zsig_encode_combined_full_viewing_key(
    fvk: *const ZsigCombinedFullViewingKey,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if fvk.is_null() || output.is_null() || output_len < 512 {
        return 0;
    }

    let fvk_ref = &*fvk;

    // Combined UFVK format (ZIP-316):
    // TLV receivers ordered by typecode ascending
    //
    // Transparent P2PKH FVK: [0x00] || [65] || chain_code (32) || pubkey (33) = 67 bytes
    // Sapling FVK:           [0x02] || [128] || ak (32) || nk (32) || ovk (32) || dk (32) = 130 bytes
    // Orchard FVK:           [0x03] || [96] || ak (32) || nk (32) || rivk (32) = 98 bytes
    // Total TLV: 67 + 130 + 98 = 295 bytes
    // + 16 bytes HRP padding = 311 bytes

    let hrp = if mainnet { "uview" } else { "uviewtest" };

    // Build TLV + padding
    let mut raw = [0u8; 311];

    // Transparent P2PKH FVK (typecode 0x00) - ZIP-316 format
    raw[0] = 0x00;  // Transparent P2PKH type
    raw[1] = 65;    // Length: 32 (chain_code) + 33 (pubkey) = 65 bytes
    raw[2..34].copy_from_slice(&fvk_ref.transparent.chain_code);
    raw[34..67].copy_from_slice(&fvk_ref.transparent.pubkey);

    // Sapling FVK (typecode 0x02)
    raw[67] = 0x02;   // Sapling type
    raw[68] = 128;    // Length: 32 + 32 + 32 + 32 = 128 bytes
    raw[69..101].copy_from_slice(&fvk_ref.sapling.ak);
    raw[101..133].copy_from_slice(&fvk_ref.sapling.nk);
    raw[133..165].copy_from_slice(&fvk_ref.sapling.ovk);
    raw[165..197].copy_from_slice(&fvk_ref.sapling.dk);

    // Orchard FVK (typecode 0x03)
    raw[197] = 0x03; // Orchard type
    raw[198] = 96;   // Length: 32 + 32 + 32
    raw[199..231].copy_from_slice(&fvk_ref.orchard.ak);
    raw[231..263].copy_from_slice(&fvk_ref.orchard.nk);
    raw[263..295].copy_from_slice(&fvk_ref.orchard.rivk);

    // Append HRP right-padded with zeros to 16 bytes
    let hrp_bytes = hrp.as_bytes();
    raw[295..295 + hrp_bytes.len()].copy_from_slice(hrp_bytes);
    // Remaining bytes [295+hrp_len..311] are already zeros

    // Apply F4Jumble
    let mut jumbled = [0u8; 311];
    if !f4_jumble(&raw, &mut jumbled) {
        return 0;
    }

    // Convert to 5-bit groups for Bech32m
    let data_5bit = to_5bit_groups(&jumbled);

    // Build the Bech32m string
    let encoded = match bech32_encode(hrp, &data_5bit) {
        Some(s) => s,
        None => return 0,
    };

    let len = encoded.len();
    if len >= output_len {
        return 0;
    }

    let output_slice = slice::from_raw_parts_mut(output, len + 1);
    output_slice[..len].copy_from_slice(encoded.as_bytes());
    output_slice[len] = 0; // Null terminator

    len
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// BLAKE2b hash with personalization
///
/// Generic BLAKE2b hash function with 16-byte personalization.
/// Used for F4Jumble decoding and other purposes.
///
/// # Safety
/// - `personal` must point to `personal_len` bytes (typically 16)
/// - `data` must point to `data_len` bytes
/// - `output` must point to a buffer of at least `output_len` bytes
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn zsig_blake2b_personal(
    personal: *const u8,
    personal_len: usize,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if personal.is_null() || data.is_null() || output.is_null() {
        return -1;
    }

    if personal_len != 16 || output_len == 0 || output_len > 64 {
        return -1;
    }

    let personal_slice = slice::from_raw_parts(personal, personal_len);
    let data_slice = slice::from_raw_parts(data, data_len);

    let mut pers_array = [0u8; 16];
    pers_array.copy_from_slice(personal_slice);

    let result = Params::new()
        .hash_length(output_len)
        .personal(&pers_array)
        .hash(data_slice);

    let output_slice = slice::from_raw_parts_mut(output, output_len);
    output_slice.copy_from_slice(&result.as_bytes()[..output_len]);

    0
}

/// Derive Combined UFVK from seed as a bech32m string
///
/// Convenience function that combines derivation and encoding.
/// Returns the length of the encoded string (excluding null terminator),
/// or negative error code on failure.
///
/// # Safety
/// - `seed` must point to `seed_len` valid bytes
/// - `output` must point to a buffer of at least `output_len` bytes
/// - `output_len` must be at least 512
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_combined_ufvk_string(
    seed: *const u8,
    seed_len: usize,
    coin_type: u32,
    account: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if seed.is_null() || output.is_null() || output_len < 512 {
        return -1;
    }

    // Derive combined FVK
    let mut fvk = ZsigCombinedFullViewingKey {
        transparent: ZsigTransparentFullViewingKey {
            chain_code: [0u8; 32],
            pubkey: [0u8; 33],
        },
        sapling: ZsigSaplingFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            ovk: [0u8; 32],
            dk: [0u8; 32],
        },
        orchard: ZsigOrchardFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            rivk: [0u8; 32],
        },
    };

    let result = zsig_derive_combined_full_viewing_key(
        seed,
        seed_len,
        coin_type,
        account,
        &mut fvk,
    );

    if result as i32 != 0 {
        return -(result as i32);
    }

    let len = zsig_encode_combined_full_viewing_key(&fvk, mainnet, output, output_len);

    if len == 0 {
        return -100; // Encoding failed
    }

    len as i32
}
