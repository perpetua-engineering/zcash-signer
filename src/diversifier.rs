//! Diversifier derivation using FF1-AES256
//!
//! Implements ZIP-32 diversifier derivation:
//! - FF1-AES256 encryption to convert index → diversifier
//! - Sapling DiversifyHash to check validity
//!
//! Reference: https://zips.z.cash/zip-0032

use aes::Aes256;
use fpe::ff1::{BinaryNumeralString, FF1};

/// First 64 bytes of GroupHash^J input as specified by sapling-crypto.
const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

/// BLAKE2s personalization for Sapling key diversification group hash.
const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

// -----------------------------------------------------------------------------
// FF1-AES256 Implementation
// -----------------------------------------------------------------------------

fn ff1_encrypt_diversifier(ff1: &FF1<Aes256>, input: &[u8; 11]) -> [u8; 11] {
    let encrypted = ff1
        .encrypt(&[], &BinaryNumeralString::from_bytes_le(input))
        .expect("FF1-AES256 encrypt failed for 88-bit radix-2 input");
    let encrypted_bytes = encrypted.to_bytes_le();
    encrypted_bytes
        .as_slice()
        .try_into()
        .expect("FF1-AES256 output must be 11 bytes")
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
    let ff1 = FF1::<Aes256>::new(dk, 2).expect("FF1-AES256 init failed");

    // Convert index to 11-byte little-endian representation
    let mut input = [0u8; 11];
    input[..8].copy_from_slice(&index.to_le_bytes());

    ff1_encrypt_diversifier(&ff1, &input)
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
    use group::GroupEncoding;
    use jubjub::ExtendedPoint;

    // Mirrors sapling-crypto::group_hash::group_hash(tag, b"Zcash_gd")
    // where tag is the 11-byte diversifier.
    let hash = blake2s_simd::Params::new()
        .hash_length(32)
        .personal(KEY_DIVERSIFICATION_PERSONALIZATION)
        .to_state()
        .update(GH_FIRST_BLOCK)
        .update(diversifier)
        .finalize();

    let point_opt = ExtendedPoint::from_bytes(hash.as_array());
    if point_opt.is_none().into() {
        return false;
    }

    let cleared = point_opt.unwrap().clear_cofactor();
    !bool::from(cleared.is_identity())
}

/// Find the first valid Sapling diversifier index
///
/// Starting from index 0, find the first index where the diversifier
/// produces a valid Sapling address (DiversifyHash doesn't return ⊥).
///
/// Returns the index and the diversifier bytes.
pub fn find_first_valid_diversifier(dk: &[u8; 32]) -> (u64, [u8; 11]) {
    let ff1 = FF1::<Aes256>::new(dk, 2).expect("FF1-AES256 init failed");

    for index in 0..u64::MAX {
        let mut input = [0u8; 11];
        input[..8].copy_from_slice(&index.to_le_bytes());
        let diversifier = ff1_encrypt_diversifier(&ff1, &input);
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

use crate::ZsigError;
use core::slice;

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
