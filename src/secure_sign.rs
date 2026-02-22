//! Secure PCZT signing — keeps seed in C++/Rust, never exposed to Swift.
//!
//! Decrypts the SE-encrypted mnemonic via wallet-core's `TWSecureSignerDeriveSeed`,
//! derives all needed keys in Rust memory with `Zeroizing` wrappers, signs the PCZT,
//! and drops (zeroizes) everything on return.
//!
//! Feature-gated behind `secure-signer` to avoid link errors when building without
//! wallet-core.

use alloc::boxed::Box;
use core::ffi::{c_char, c_void};
use core::slice;

use zeroize::Zeroizing;

use crate::keys::{derive_orchard_ask_bytes, derive_orchard_sk, derive_sapling_ask_bytes};
use crate::pczt_signer::{sign_pczt, PcztSigningKeys};
use crate::transparent::derive_transparent_sk;
use crate::ZsigError;

// -----------------------------------------------------------------------------
// Wallet-core C FFI (provided at link time by Trust Wallet Core)
// -----------------------------------------------------------------------------

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

/// Maximum PCZT payload size (1 MB).
const MAX_PCZT_LEN: usize = 1024 * 1024;

// -----------------------------------------------------------------------------
// Core Implementation
// -----------------------------------------------------------------------------

/// Decrypt the mnemonic, derive keys, sign the PCZT, and zeroize everything.
///
/// Returns the signed PCZT bytes on success, or a `ZsigError` on failure.
fn pczt_sign_secure(
    encrypted_mnemonic: &[u8],
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    pczt_data: &[u8],
    coin_type: u32,
    account: u32,
) -> Result<alloc::vec::Vec<u8>, ZsigError> {
    // ── 1. Call wallet-core to decrypt the mnemonic → seed ──────────────
    let tw_mnemonic = unsafe { TWDataCreateWithBytes(encrypted_mnemonic.as_ptr(), encrypted_mnemonic.len()) };
    if tw_mnemonic.is_null() {
        return Err(ZsigError::SeedDerivationFailed);
    }

    let tw_salt = unsafe { TWStringCreateWithUTF8Bytes(hkdf_salt) };
    if tw_salt.is_null() {
        unsafe { TWDataDelete(tw_mnemonic) };
        return Err(ZsigError::SeedDerivationFailed);
    }

    let tw_seed = unsafe { TWSecureSignerDeriveSeed(tw_mnemonic, se_key_ref, tw_salt) };

    // Clean up input wrappers immediately.
    unsafe {
        TWDataDelete(tw_mnemonic);
        TWStringDelete(tw_salt);
    }

    if tw_seed.is_null() {
        return Err(ZsigError::SeedDerivationFailed);
    }

    // ── 2. Copy seed into Zeroizing buffer, free wallet-core's copy ────
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

    // ── 3. Parse the PCZT to see which key types are needed ────────────
    let pczt = pczt::Pczt::parse(pczt_data).map_err(|_| ZsigError::PcztParseFailed)?;
    let has_orchard = !pczt.orchard().actions().is_empty();
    let has_sapling = !pczt.sapling().spends().is_empty();
    let has_transparent = !pczt.transparent().inputs().is_empty();
    drop(pczt); // Free the parsed PCZT before signing (sign_pczt re-parses)

    // ── 4. Derive only the keys we need ────────────────────────────────
    let orchard_sk = if has_orchard {
        let sk = Zeroizing::new(derive_orchard_sk(&*seed, coin_type, account));
        Some(sk)
    } else {
        None
    };

    let orchard_ask = orchard_sk.as_ref().map(|sk| {
        Zeroizing::new(derive_orchard_ask_bytes(sk))
    });
    // We need the spending key (not ask) for sign_pczt's orchard_sk field.
    // orchard_ask is unused directly — sign_pczt derives ask internally from sk.
    let _ = orchard_ask;

    let sapling_ask = if has_sapling {
        Some(Zeroizing::new(derive_sapling_ask_bytes(&*seed, coin_type, account)))
    } else {
        None
    };

    let transparent_sk = if has_transparent {
        let sk = derive_transparent_sk(&*seed, coin_type, account)
            .ok_or(ZsigError::InvalidKey)?;
        Some(Zeroizing::new(sk))
    } else {
        None
    };

    // Seed is no longer needed — drop it now (zeroizes).
    drop(seed);

    // ── 5. Sign the PCZT ───────────────────────────────────────────────
    let keys = PcztSigningKeys {
        orchard_sk: orchard_sk.as_deref(),
        sapling_ask: sapling_ask.as_deref(),
        transparent_sk: transparent_sk.as_deref(),
    };

    let signed = sign_pczt(pczt_data, &keys).map_err(|e| {
        use crate::pczt_signer::PcztSignError;
        match e {
            PcztSignError::ParseFailed => ZsigError::PcztParseFailed,
            PcztSignError::InvalidOrchardKey
            | PcztSignError::InvalidSaplingKey
            | PcztSignError::InvalidTransparentKey => ZsigError::PcztInvalidKey,
            PcztSignError::OrchardSignFailed
            | PcztSignError::SaplingSignFailed
            | PcztSignError::TransparentSignFailed => ZsigError::PcztSignFailed,
        }
    })?;

    // All Zeroizing wrappers drop here → keys wiped.
    Ok(signed)
}

// -----------------------------------------------------------------------------
// C FFI
// -----------------------------------------------------------------------------

/// Sign a PCZT using an SE-encrypted mnemonic (seed never leaves C++/Rust).
///
/// The signed PCZT is heap-allocated and returned via `out_signed_pczt` / `out_len`.
/// The caller must free the buffer with `zsig_free(ptr, len)`.
///
/// # Safety
/// - `encrypted_mnemonic` must point to `encrypted_mnemonic_len` readable bytes
/// - `se_key_ref` is an opaque pointer passed through to wallet-core
/// - `hkdf_salt` must be a null-terminated C string
/// - `pczt_data` must point to `pczt_len` readable bytes
/// - `out_signed_pczt` and `out_len` must point to writable memory
#[no_mangle]
pub unsafe extern "C" fn zsig_pczt_sign_secure(
    encrypted_mnemonic: *const u8,
    encrypted_mnemonic_len: usize,
    se_key_ref: *const c_void,
    hkdf_salt: *const c_char,
    pczt_data: *const u8,
    pczt_len: usize,
    coin_type: u32,
    account: u32,
    out_signed_pczt: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // Null checks.
    if encrypted_mnemonic.is_null()
        || hkdf_salt.is_null()
        || pczt_data.is_null()
        || out_signed_pczt.is_null()
        || out_len.is_null()
    {
        return ZsigError::NullPointer as i32;
    }

    if encrypted_mnemonic_len == 0 {
        return ZsigError::InvalidSeed as i32;
    }

    if pczt_len == 0 || pczt_len > MAX_PCZT_LEN {
        return ZsigError::BufferTooSmall as i32;
    }

    let enc_slice = slice::from_raw_parts(encrypted_mnemonic, encrypted_mnemonic_len);
    let pczt_slice = slice::from_raw_parts(pczt_data, pczt_len);

    match pczt_sign_secure(enc_slice, se_key_ref, hkdf_salt, pczt_slice, coin_type, account) {
        Ok(signed) => {
            let len = signed.len();
            let boxed = signed.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut u8;
            *out_signed_pczt = ptr;
            *out_len = len;
            ZsigError::Success as i32
        }
        Err(e) => {
            *out_signed_pczt = core::ptr::null_mut();
            *out_len = 0;
            e as i32
        }
    }
}
