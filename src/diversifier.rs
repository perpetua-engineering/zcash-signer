//! Diversifier derivation using FF1-AES256
//!
//! Implements ZIP-32 diversifier derivation:
//! - FF1-AES256 encryption to convert index → diversifier
//! - Sapling DiversifyHash to check validity
//!
//! Reference: https://zips.z.cash/zip-0032

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use alloc::vec;
use alloc::vec::Vec;

/// GroupHash^J personalization for URS generation
const GH_FIRST_BLOCK_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

/// BLAKE2s personalization for GroupHash^J (8 bytes for BLAKE2s)
const BLAKE2S_PERSONALIZATION: &[u8; 8] = b"Zcash_PH";

// -----------------------------------------------------------------------------
// FF1-AES256 Implementation
// -----------------------------------------------------------------------------

/// FF1-AES256 encryption for diversifier derivation
///
/// This implements the FF1 format-preserving encryption algorithm from NIST SP 800-38G
/// with AES-256 as the underlying block cipher.
///
/// For Zcash diversifier derivation:
/// - radix = 2 (binary)
/// - minlen = maxlen = 88 bits (11 bytes)
/// - tweak = "" (empty)
///
/// Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
pub struct Ff1Aes256 {
    cipher: Aes256,
}

impl Ff1Aes256 {
    /// Create a new FF1-AES256 instance with the given 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        Self { cipher }
    }

    /// Encrypt an 11-byte diversifier using FF1
    ///
    /// This converts a diversifier index to the actual diversifier bytes.
    pub fn encrypt(&self, input: &[u8; 11]) -> [u8; 11] {
        // FF1 parameters for 88-bit (11-byte) diversifiers
        // radix = 2, n = 88
        // u = floor(88/2) = 44
        // v = 88 - 44 = 44

        let _n = 88u32; // Total bits (for documentation; u + v)
        let u = 44u32; // Left half bits
        let v = 44u32; // Right half bits

        // Split input into left (A) and right (B) halves
        // A = bits [0..44), B = bits [44..88)
        let mut a = extract_bits(input, 0, u as usize);
        let mut b = extract_bits(input, u as usize, v as usize);

        // 10 rounds of Feistel
        for i in 0..10u8 {
            let c = self.prf(&b, i, v);
            let c_num = bits_to_num(&c, v as usize);
            let a_num = bits_to_num(&a, u as usize);

            // c = (a + c) mod 2^u
            let new_a_num = (a_num + c_num) % (1u128 << u);
            let new_a = num_to_bits(new_a_num, u as usize);

            a = b;
            b = new_a;
        }

        // Combine A || B back into output
        combine_bits(&a, &b, u as usize, v as usize)
    }

    /// PRF function for FF1: AES-CBC-MAC based
    fn prf(&self, data: &[u8], round: u8, v: u32) -> Vec<u8> {
        // Build the input block for AES
        // P = [1]^1 || [2]^1 || [1]^1 || [radix=2]^3 || [10]^1 || [u mod 256]^1 ||
        //     [n]^4 || [t=0]^4
        // Q = [0]^(-t-b-1 mod 16) || [i]^1 || [B as numradix]

        // For our case: t=0 (empty tweak), radix=2, n=88
        // Simplified P block (16 bytes)
        let mut p = [0u8; 16];
        p[0] = 1;      // version
        p[1] = 2;      // method
        p[2] = 1;      // addition
        p[3] = 0;      // radix high byte (radix=2)
        p[4] = 0;      // radix mid byte
        p[5] = 2;      // radix low byte
        p[6] = 10;     // number of rounds
        p[7] = (v % 256) as u8; // u mod 256 = 44
        p[8..12].copy_from_slice(&88u32.to_be_bytes()); // n = 88
        p[12..16].copy_from_slice(&0u32.to_be_bytes()); // t = 0

        // Encrypt P to get R
        let mut r = GenericArray::clone_from_slice(&p);
        self.cipher.encrypt_block(&mut r);

        // Build Q: pad || round || data
        // b = ceil(ceil(v * log2(radix)) / 8) = ceil(44 / 8) = 6
        let b = 6usize;
        let pad_len = (16 - 1 - b) % 16;

        let mut q = vec![0u8; pad_len + 1 + b];
        q[pad_len] = round;

        // Copy data bytes (right-aligned)
        let data_start = pad_len + 1 + b - data.len().min(b);
        q[data_start..pad_len + 1 + b].copy_from_slice(&data[..data.len().min(b)]);

        // CBC-MAC: XOR Q blocks with R and encrypt
        for chunk in q.chunks(16) {
            let mut block = [0u8; 16];
            for (i, &byte) in chunk.iter().enumerate() {
                block[i] = r[i] ^ byte;
            }
            r = GenericArray::clone_from_slice(&block);
            self.cipher.encrypt_block(&mut r);
        }

        // Return first d bytes where d = ceil(v / 8) = 6
        let d = ((v + 7) / 8) as usize;
        r[..d].to_vec()
    }
}

/// Extract `count` bits starting at `start` from the input
fn extract_bits(input: &[u8; 11], start: usize, count: usize) -> Vec<u8> {
    let mut result = vec![0u8; (count + 7) / 8];

    for i in 0..count {
        let src_bit = start + i;
        let src_byte = src_bit / 8;
        let src_bit_idx = src_bit % 8;

        let dst_bit = i;
        let dst_byte = dst_bit / 8;
        let dst_bit_idx = dst_bit % 8;

        if (input[src_byte] >> src_bit_idx) & 1 == 1 {
            result[dst_byte] |= 1 << dst_bit_idx;
        }
    }

    result
}

/// Convert bits to a number (little-endian)
fn bits_to_num(bits: &[u8], count: usize) -> u128 {
    let mut result = 0u128;
    for i in 0..count {
        let byte = i / 8;
        let bit = i % 8;
        if byte < bits.len() && (bits[byte] >> bit) & 1 == 1 {
            result |= 1u128 << i;
        }
    }
    result
}

/// Convert a number to bits (little-endian)
fn num_to_bits(num: u128, count: usize) -> Vec<u8> {
    let mut result = vec![0u8; (count + 7) / 8];
    for i in 0..count {
        if (num >> i) & 1 == 1 {
            result[i / 8] |= 1 << (i % 8);
        }
    }
    result
}

/// Combine two bit arrays into an 11-byte output
fn combine_bits(a: &[u8], b: &[u8], a_bits: usize, b_bits: usize) -> [u8; 11] {
    let mut result = [0u8; 11];

    // Copy A bits [0..a_bits)
    for i in 0..a_bits {
        let src_byte = i / 8;
        let src_bit = i % 8;
        let dst_byte = i / 8;
        let dst_bit = i % 8;

        if src_byte < a.len() && (a[src_byte] >> src_bit) & 1 == 1 {
            result[dst_byte] |= 1 << dst_bit;
        }
    }

    // Copy B bits [a_bits..a_bits+b_bits)
    for i in 0..b_bits {
        let src_byte = i / 8;
        let src_bit = i % 8;
        let dst_idx = a_bits + i;
        let dst_byte = dst_idx / 8;
        let dst_bit = dst_idx % 8;

        if src_byte < b.len() && (b[src_byte] >> src_bit) & 1 == 1 {
            result[dst_byte] |= 1 << dst_bit;
        }
    }

    result
}

// -----------------------------------------------------------------------------
// Diversifier Derivation
// -----------------------------------------------------------------------------

/// Derive diversifier from diversifier key and index
///
/// d_j = FF1-AES256.Encrypt(dk, "", I2LEOSP_88(j))
///
/// This converts an index (0, 1, 2, ...) to an 11-byte diversifier.
pub fn derive_diversifier(dk: &[u8; 32], index: u64) -> [u8; 11] {
    let ff1 = Ff1Aes256::new(dk);

    // Convert index to 11-byte little-endian representation
    let mut input = [0u8; 11];
    input[..8].copy_from_slice(&index.to_le_bytes());

    ff1.encrypt(&input)
}

/// Check if a Sapling diversifier is valid
///
/// A diversifier is valid if DiversifyHash^Sapling(d) returns a valid point
/// on the Jubjub curve (not the identity/infinity point).
///
/// DiversifyHash is implemented as GroupHash^J("Zcash_gd", diversifier):
/// 1. BLAKE2s-256 with "Zcash_PH" personalization, input = "Zcash_gd" || diversifier
/// 2. Interpret result as compressed Jubjub point
/// 3. Clear cofactor (multiply by 8)
/// 4. Valid if result is not identity
pub fn is_valid_sapling_diversifier(diversifier: &[u8; 11]) -> bool {
    use group::cofactor::CofactorGroup;
    use group::Group;
    use jubjub::{AffinePoint, ExtendedPoint};

    // GroupHash^J(D, M) where D = "Zcash_gd" and M = diversifier
    // Uses BLAKE2s-256 with "Zcash_PH" personalization
    // Input is D || M = "Zcash_gd" || diversifier

    // Build input: domain || diversifier
    let mut input = [0u8; 19]; // 8 + 11
    input[..8].copy_from_slice(GH_FIRST_BLOCK_PERSONALIZATION);
    input[8..].copy_from_slice(diversifier);

    // BLAKE2s-256 with proper personalization
    let hash = blake2s_simd::Params::new()
        .hash_length(32)
        .personal(BLAKE2S_PERSONALIZATION)
        .hash(&input);

    // Try to interpret the hash as a compressed Jubjub point
    let point_bytes: [u8; 32] = hash.as_bytes().try_into().unwrap();
    let point_opt = AffinePoint::from_bytes(point_bytes);
    if point_opt.is_none().into() {
        return false;
    }

    // Clear cofactor by multiplying by 8
    let point: AffinePoint = point_opt.unwrap();
    let extended: ExtendedPoint = point.into();
    let cleared = extended.clear_cofactor();

    // Valid if not identity
    !bool::from(cleared.is_identity())
}

/// Find the first valid Sapling diversifier index
///
/// Starting from index 0, find the first index where the diversifier
/// produces a valid Sapling address (DiversifyHash doesn't return ⊥).
///
/// Returns the index and the diversifier bytes.
pub fn find_first_valid_diversifier(dk: &[u8; 32]) -> (u64, [u8; 11]) {
    for index in 0..u64::MAX {
        let diversifier = derive_diversifier(dk, index);
        if is_valid_sapling_diversifier(&diversifier) {
            return (index, diversifier);
        }
    }

    // This should never happen in practice - roughly half of diversifiers are valid
    panic!("No valid diversifier found");
}

// -----------------------------------------------------------------------------
// FFI Functions
// -----------------------------------------------------------------------------

use core::slice;
use crate::ZsigError;

/// Find the first valid Sapling diversifier index for a given diversifier key
///
/// This searches for the first index where DiversifyHash produces a valid point.
/// The diversifier key (dk) is derived from the Sapling spending key.
///
/// # Safety
/// - `dk` must point to 32 readable bytes
/// - `index_out` must point to a writable u64
/// - `diversifier_out` must point to 11 writable bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_find_valid_diversifier(
    dk: *const u8,
    index_out: *mut u64,
    diversifier_out: *mut u8,
) -> ZsigError {
    if dk.is_null() || index_out.is_null() || diversifier_out.is_null() {
        return ZsigError::NullPointer;
    }

    let dk_slice: [u8; 32] = slice::from_raw_parts(dk, 32).try_into().unwrap();
    let (index, diversifier) = find_first_valid_diversifier(&dk_slice);

    *index_out = index;
    slice::from_raw_parts_mut(diversifier_out, 11).copy_from_slice(&diversifier);

    ZsigError::Success
}

/// Derive a diversifier from diversifier key and index
///
/// # Safety
/// - `dk` must point to 32 readable bytes
/// - `diversifier_out` must point to 11 writable bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_diversifier(
    dk: *const u8,
    index: u64,
    diversifier_out: *mut u8,
) -> ZsigError {
    if dk.is_null() || diversifier_out.is_null() {
        return ZsigError::NullPointer;
    }

    let dk_slice: [u8; 32] = slice::from_raw_parts(dk, 32).try_into().unwrap();
    let diversifier = derive_diversifier(&dk_slice, index);

    slice::from_raw_parts_mut(diversifier_out, 11).copy_from_slice(&diversifier);

    ZsigError::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_diversifier_deterministic() {
        let dk = [0u8; 32];
        let d0 = derive_diversifier(&dk, 0);
        let d1 = derive_diversifier(&dk, 1);

        // Different indices should give different diversifiers
        assert_ne!(d0, d1);

        // Same index should give same diversifier
        let d0_again = derive_diversifier(&dk, 0);
        assert_eq!(d0, d0_again);
    }

    #[test]
    fn test_find_valid_diversifier() {
        let dk = [0u8; 32];
        let (index, diversifier) = find_first_valid_diversifier(&dk);

        // Should find a valid diversifier
        assert!(is_valid_sapling_diversifier(&diversifier));

        // Index should be reasonable (usually < 10 for most keys)
        assert!(index < 100, "First valid index {} seems too high", index);
    }
}
