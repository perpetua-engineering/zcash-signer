//! Secure address/key derivation — decrypts SE-encrypted mnemonic in C++/Rust,
//! derives the requested value, and zeroizes the seed before returning.
//!
//! Follows the same pattern as `secure_sign.rs` for PCZT signing.
//! Feature-gated behind `secure-signer` to avoid link errors without wallet-core.

use core::ffi::{c_char, c_void};
use core::slice;

use zeroize::Zeroizing;

use crate::address::ZsigOrchardAddress;
use crate::ZsigError;

// wallet-core C FFI (same declarations as secure_sign.rs — provided at link time)
extern "C" {
    fn TWDataCreateWithBytes(bytes: *const u8, size: usize) -> *mut c_void;
    fn TWDataBytes(data: *const c_void) -> *const u8;
    fn TWDataSize(data: *const c_void) -> usize;
    fn TWDataDelete(data: *mut c_void);
    fn TWStringCreateWithUTF8Bytes(str: *const c_char) -> *mut c_void;
    fn TWStringDelete(str: *mut c_void);
    fn TWSecureSignerDeriveSeed(
        encrypted_mnemonic: *const c_void,
        se_key_ref: *const c_void,
        hkdf_salt: *const c_void,
    ) -> *mut c_void;
    fn TWSecureSignerFreeSeed(seed: *mut c_void);
}

// Re-use existing FFI derivation functions (they take raw seed pointers)
extern "C" {
    fn zsig_derive_orchard_address_from_seed(
        seed: *const u8,
        seed_len: usize,
        coin_type: u32,
        account: u32,
        address_out: *mut ZsigOrchardAddress,
    ) -> ZsigError;

    fn zsig_encode_unified_address(
        address: *const ZsigOrchardAddress,
        mainnet: bool,
        output: *mut u8,
        output_len: usize,
    ) -> usize;

    fn zsig_derive_transparent_address(
        seed: *const u8,
        seed_len: usize,
        account: u32,
        index: u32,
        mainnet: bool,
        output: *mut u8,
        output_len: usize,
    ) -> usize;

    fn zsig_derive_transparent_pubkey_hash(
        seed: *const u8,
        seed_len: usize,
        account: u32,
        index: u32,
        hash_out: *mut u8,
    ) -> ZsigError;

    fn zsig_derive_combined_ufvk_string(
        seed: *const u8,
        seed_len: usize,
        coin_type: u32,
        account: u32,
        mainnet: bool,
        output: *mut u8,
        output_len: usize,
    ) -> i32;

    fn zsig_derive_first_valid_diversifier_index(
        seed: *const u8,
        seed_len: usize,
        coin_type: u32,
        account: u32,
        index_out: *mut u64,
        diversifier_out: *mut u8,
    ) -> ZsigError;
}

// ---------------------------------------------------------------------------
// Shared helper: decrypt mnemonic → derive seed → zeroize C++ buffer
// ---------------------------------------------------------------------------

/// Decrypt the SE-encrypted mnemonic via wallet-core, returning the 64-byte
/// BIP-39 seed in a `Zeroizing` wrapper. The C++ buffer is freed immediately.
///
/// This is the same sequence used in `secure_sign.rs` for PCZT signing.
pub(crate) fn derive_seed_secure(
    encrypted_mnemonic: &[u8],
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
) -> Result<Zeroizing<[u8; 64]>, ZsigError> {
    let tw_mnemonic =
        unsafe { TWDataCreateWithBytes(encrypted_mnemonic.as_ptr(), encrypted_mnemonic.len()) };
    if tw_mnemonic.is_null() {
        return Err(ZsigError::SeedDerivationFailed);
    }

    let tw_salt = unsafe { TWStringCreateWithUTF8Bytes(hkdf_salt) };
    if tw_salt.is_null() {
        unsafe { TWDataDelete(tw_mnemonic) };
        return Err(ZsigError::SeedDerivationFailed);
    }

    let tw_seed = unsafe { TWSecureSignerDeriveSeed(tw_mnemonic, se_key_ref, tw_salt) };

    unsafe {
        TWDataDelete(tw_mnemonic);
        TWStringDelete(tw_salt);
    }

    if tw_seed.is_null() {
        return Err(ZsigError::SeedDerivationFailed);
    }

    let seed_len = unsafe { TWDataSize(tw_seed) };
    if seed_len != 64 {
        unsafe { TWSecureSignerFreeSeed(tw_seed) };
        return Err(ZsigError::SeedDerivationFailed);
    }

    let mut seed = Zeroizing::new([0u8; 64]);
    unsafe {
        let seed_ptr = TWDataBytes(tw_seed);
        core::ptr::copy_nonoverlapping(seed_ptr, seed.as_mut_ptr(), 64);
        TWSecureSignerFreeSeed(tw_seed);
    }

    Ok(seed)
}

// ---------------------------------------------------------------------------
// Validation helper
// ---------------------------------------------------------------------------

fn validate_common_params(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    hkdf_salt: *const c_char,
) -> Result<(), ZsigError> {
    if encrypted_mnemonic.is_null() || hkdf_salt.is_null() {
        return Err(ZsigError::NullPointer);
    }
    if encrypted_mnemonic_len == 0 {
        return Err(ZsigError::InvalidSeed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FFI: Orchard Unified Address (secure)
// ---------------------------------------------------------------------------

/// Derive Orchard unified address from SE-encrypted mnemonic.
///
/// Returns the address as a null-terminated UTF-8 string in `output`.
/// The return value is the string length (excluding null), or a negative
/// error code on failure.
///
/// # Safety
/// - `encrypted_mnemonic` must point to `encrypted_mnemonic_len` readable bytes
/// - `se_key_ref` is an opaque pointer passed through to wallet-core
/// - `hkdf_salt` must be a null-terminated C string
/// - `output` must point to at least `output_len` writable bytes (256 minimum)
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_orchard_address_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    coin_type: u32,
    account: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() || output_len < 256 {
        return -(ZsigError::BufferTooSmall as i32);
    }

    if let Err(e) = validate_common_params(encrypted_mnemonic, encrypted_mnemonic_len, hkdf_salt) {
        return -(e as i32);
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);

    let seed = match derive_seed_secure(enc_slice, se_key_ref, hkdf_salt) {
        Ok(s) => s,
        Err(e) => return -(e as i32),
    };

    // Derive Orchard address from seed
    let mut address = core::mem::MaybeUninit::<ZsigOrchardAddress>::uninit();
    let result = zsig_derive_orchard_address_from_seed(
        seed.as_ptr(),
        64,
        coin_type,
        account,
        address.as_mut_ptr(),
    );

    drop(seed); // zeroize seed

    if result != ZsigError::Success {
        return -(result as i32);
    }

    let address = address.assume_init();

    // Encode as Unified Address
    let len = zsig_encode_unified_address(&address, mainnet, output, output_len);
    if len == 0 {
        return -(ZsigError::BufferTooSmall as i32);
    }

    len as i32
}

// ---------------------------------------------------------------------------
// FFI: Transparent Address (secure)
// ---------------------------------------------------------------------------

/// Derive transparent P2PKH address from SE-encrypted mnemonic.
///
/// Returns the address length (positive) or negative error code.
///
/// # Safety
/// Same as `zsig_derive_orchard_address_secure`.
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_transparent_address_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    account: u32,
    index: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() || output_len < 64 {
        return -(ZsigError::BufferTooSmall as i32);
    }

    if let Err(e) = validate_common_params(encrypted_mnemonic, encrypted_mnemonic_len, hkdf_salt) {
        return -(e as i32);
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);

    let seed = match derive_seed_secure(enc_slice, se_key_ref, hkdf_salt) {
        Ok(s) => s,
        Err(e) => return -(e as i32),
    };

    let len = zsig_derive_transparent_address(
        seed.as_ptr(),
        64,
        account,
        index,
        mainnet,
        output,
        output_len,
    );

    drop(seed);

    if len == 0 {
        return -(ZsigError::InvalidKey as i32);
    }

    len as i32
}

// ---------------------------------------------------------------------------
// FFI: Transparent Pubkey Hash (secure)
// ---------------------------------------------------------------------------

/// Derive transparent pubkey hash (20 bytes) from SE-encrypted mnemonic.
///
/// # Safety
/// Same as `zsig_derive_orchard_address_secure`.
/// `hash_out` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_transparent_pubkey_hash_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    account: u32,
    index: u32,
    hash_out: *mut u8,
) -> i32 {
    if hash_out.is_null() {
        return ZsigError::NullPointer as i32;
    }

    if let Err(e) = validate_common_params(encrypted_mnemonic, encrypted_mnemonic_len, hkdf_salt) {
        return e as i32;
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);

    let seed = match derive_seed_secure(enc_slice, se_key_ref, hkdf_salt) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };

    let result = zsig_derive_transparent_pubkey_hash(seed.as_ptr(), 64, account, index, hash_out);

    drop(seed);

    result as i32
}

// ---------------------------------------------------------------------------
// FFI: Combined UFVK String (secure)
// ---------------------------------------------------------------------------

/// Derive Combined UFVK string from SE-encrypted mnemonic.
///
/// Returns the UFVK string length (positive) or negative error code.
///
/// # Safety
/// Same as `zsig_derive_orchard_address_secure`.
/// `output` must point to at least `output_len` bytes (512 minimum).
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_combined_ufvk_string_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    coin_type: u32,
    account: u32,
    mainnet: bool,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() || output_len < 512 {
        return -(ZsigError::BufferTooSmall as i32);
    }

    if let Err(e) = validate_common_params(encrypted_mnemonic, encrypted_mnemonic_len, hkdf_salt) {
        return -(e as i32);
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);

    let seed = match derive_seed_secure(enc_slice, se_key_ref, hkdf_salt) {
        Ok(s) => s,
        Err(e) => return -(e as i32),
    };

    let len = zsig_derive_combined_ufvk_string(
        seed.as_ptr(),
        64,
        coin_type,
        account,
        mainnet,
        output,
        output_len,
    );

    drop(seed);

    len // already positive on success, negative on error
}

// ---------------------------------------------------------------------------
// FFI: First Valid Diversifier Index (secure)
// ---------------------------------------------------------------------------

/// Derive first valid diversifier index from SE-encrypted mnemonic.
///
/// # Safety
/// Same as `zsig_derive_orchard_address_secure`.
/// `index_out` must point to writable u64.
/// `diversifier_out` may be NULL; if non-NULL must point to 11 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_first_valid_diversifier_index_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    coin_type: u32,
    account: u32,
    index_out: *mut u64,
    diversifier_out: *mut u8,
) -> i32 {
    if index_out.is_null() {
        return ZsigError::NullPointer as i32;
    }

    if let Err(e) = validate_common_params(encrypted_mnemonic, encrypted_mnemonic_len, hkdf_salt) {
        return e as i32;
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);

    let seed = match derive_seed_secure(enc_slice, se_key_ref, hkdf_salt) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };

    let result = zsig_derive_first_valid_diversifier_index(
        seed.as_ptr(),
        64,
        coin_type,
        account,
        index_out,
        diversifier_out,
    );

    drop(seed);

    result as i32
}
