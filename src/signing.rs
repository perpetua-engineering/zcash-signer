//! RedPallas/RedJubjub signing for Orchard and Sapling
//!
//! Implements randomized signing for PCZT (Partially Created Zcash Transaction)

use core::slice;
use crate::{ZsigError, ZsigOrchardAsk, ZsigOrchardSignature, ZsigSaplingAsk, ZsigSaplingSignature, CallbackRng, ZsigRngCallback};
use ff::PrimeField;
use pasta_curves::pallas::Scalar as PallasScalar;
use jubjub::Fr as JubjubScalar;
use reddsa::orchard::SpendAuth as OrchardSpendAuth;
use reddsa::sapling::SpendAuth as SaplingSpendAuth;

// -----------------------------------------------------------------------------
// FFI Functions
// -----------------------------------------------------------------------------

/// Sign a message using RedPallas with randomized key
///
/// For PCZT signing, each Orchard spend has an alpha randomizer.
/// The signature must verify against rk = ak + [alpha]G, so we sign
/// with the randomized key: ask_randomized = ask + alpha.
///
/// This is the main signing function used by the watch for PCZT signing.
///
/// # Safety
/// - `ask` must point to a valid ZsigOrchardAsk
/// - `alpha` must point to 32 readable bytes (the randomizer scalar from PCZT)
/// - `sighash` must point to 32 readable bytes (the transaction sighash)
/// - `signature_out` must point to valid memory for a ZsigOrchardSignature
/// - `rng_callback` must be a valid function pointer for SecRandomCopyBytes
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_orchard_randomized(
    ask: *const ZsigOrchardAsk,
    alpha: *const u8,
    sighash: *const u8,
    signature_out: *mut ZsigOrchardSignature,
    rng_callback: ZsigRngCallback,
) -> ZsigError {
    if ask.is_null() || alpha.is_null() || sighash.is_null() || signature_out.is_null() {
        return ZsigError::NullPointer;
    }

    let mut rng = CallbackRng::new(rng_callback);
    let sighash_bytes: [u8; 32] = slice::from_raw_parts(sighash, 32).try_into().unwrap();
    let ask_bytes = (*ask).bytes;
    let alpha_bytes: [u8; 32] = slice::from_raw_parts(alpha, 32).try_into().unwrap();

    // Parse both scalars
    let ask_opt = PallasScalar::from_repr(ask_bytes.into());
    let ask_scalar: PallasScalar = match Option::<PallasScalar>::from(ask_opt) {
        Some(s) => s,
        None => return ZsigError::ScalarConversionFailed,
    };

    let alpha_opt = PallasScalar::from_repr(alpha_bytes.into());
    let alpha_scalar: PallasScalar = match Option::<PallasScalar>::from(alpha_opt) {
        Some(s) => s,
        None => return ZsigError::ScalarConversionFailed,
    };

    // Compute randomized signing key: ask + alpha (mod q)
    // This is the core PCZT signing operation
    let ask_randomized: PallasScalar = ask_scalar + alpha_scalar;

    // Convert back to bytes for reddsa SigningKey
    let randomized_bytes: [u8; 32] = ask_randomized.to_repr().into();

    // Create SigningKey from randomized bytes
    let sk: reddsa::SigningKey<OrchardSpendAuth> = match reddsa::SigningKey::try_from(randomized_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Sign the sighash
    let sig: reddsa::Signature<OrchardSpendAuth> = sk.sign(&mut rng, &sighash_bytes);

    if rng.has_failed() {
        return ZsigError::RngFailed;
    }

    // Extract signature bytes
    (*signature_out).bytes = sig.into();

    ZsigError::Success
}

/// Maximum message length for non-randomized signing (1 MB)
const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Sign a message using RedPallas (non-randomized)
///
/// This is for testing or cases where no randomization is needed.
///
/// # Safety
/// - `ask` must point to a valid ZsigOrchardAsk
/// - `message` must point to `message_len` readable bytes
/// - `signature_out` must point to valid memory for a ZsigOrchardSignature
/// - `rng_callback` must be a valid function pointer for SecRandomCopyBytes
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_orchard(
    ask: *const ZsigOrchardAsk,
    message: *const u8,
    message_len: usize,
    signature_out: *mut ZsigOrchardSignature,
    rng_callback: ZsigRngCallback,
) -> ZsigError {
    if ask.is_null() || message.is_null() || signature_out.is_null() {
        return ZsigError::NullPointer;
    }

    if message_len > MAX_MESSAGE_LEN {
        return ZsigError::BufferTooSmall;
    }

    let mut rng = CallbackRng::new(rng_callback);
    let msg = slice::from_raw_parts(message, message_len);
    let ask_bytes = (*ask).bytes;

    // Create SigningKey from ask bytes
    let sk: reddsa::SigningKey<OrchardSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Sign the message
    let sig: reddsa::Signature<OrchardSpendAuth> = sk.sign(&mut rng, msg);

    if rng.has_failed() {
        return ZsigError::RngFailed;
    }

    // Extract signature bytes
    (*signature_out).bytes = sig.into();

    ZsigError::Success
}

/// Verify a RedPallas signature (for testing)
///
/// # Safety
/// - `ak` must point to 32 readable bytes (authorization key / verification key)
/// - `message` must point to `message_len` readable bytes
/// - `signature` must point to a valid ZsigOrchardSignature
#[no_mangle]
pub unsafe extern "C" fn zsig_verify_orchard(
    ak: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const ZsigOrchardSignature,
) -> ZsigError {
    if ak.is_null() || message.is_null() || signature.is_null() {
        return ZsigError::NullPointer;
    }

    if message_len > MAX_MESSAGE_LEN {
        return ZsigError::BufferTooSmall;
    }

    let ak_bytes: [u8; 32] = slice::from_raw_parts(ak, 32).try_into().unwrap();
    let msg = slice::from_raw_parts(message, message_len);
    let sig_bytes = (*signature).bytes;

    // Convert bytes to reddsa types
    let vk: reddsa::VerificationKey<OrchardSpendAuth> = match reddsa::VerificationKey::try_from(ak_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    let sig: reddsa::Signature<OrchardSpendAuth> = reddsa::Signature::from(sig_bytes);

    // Verify the signature
    match vk.verify(msg, &sig) {
        Ok(()) => ZsigError::Success,
        Err(_) => ZsigError::InvalidSignature,
    }
}

/// Derive ak (authorization key) from ask
///
/// ak = ask * G where G is the Orchard SpendAuth basepoint
///
/// # Safety
/// - `ask` must point to a valid ZsigOrchardAsk
/// - `ak_out` must point to 32 writable bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_ak_from_ask(
    ask: *const ZsigOrchardAsk,
    ak_out: *mut u8,
) -> ZsigError {
    if ask.is_null() || ak_out.is_null() {
        return ZsigError::NullPointer;
    }

    let ask_bytes = (*ask).bytes;

    // Create SigningKey from ask bytes
    let sk: reddsa::SigningKey<OrchardSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Derive verification key (ak)
    let vk: reddsa::VerificationKey<OrchardSpendAuth> = reddsa::VerificationKey::from(&sk);
    let ak_bytes: [u8; 32] = vk.into();

    // Copy to output
    let out_slice = slice::from_raw_parts_mut(ak_out, 32);
    out_slice.copy_from_slice(&ak_bytes);

    ZsigError::Success
}

// -----------------------------------------------------------------------------
// Sapling FFI Functions
// -----------------------------------------------------------------------------

/// Sign a message using RedJubjub with randomized key
///
/// For PCZT signing, each Sapling spend has an alpha randomizer.
/// The signature must verify against rk = ak + [alpha]G, so we sign
/// with the randomized key: ask_randomized = ask + alpha.
///
/// This is the main signing function used by the watch for PCZT Sapling signing.
///
/// # Safety
/// - `ask` must point to a valid ZsigSaplingAsk
/// - `alpha` must point to 32 readable bytes (the randomizer scalar from PCZT)
/// - `sighash` must point to 32 readable bytes (the transaction sighash)
/// - `signature_out` must point to valid memory for a ZsigSaplingSignature
/// - `rng_callback` must be a valid function pointer for SecRandomCopyBytes
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_sapling_randomized(
    ask: *const ZsigSaplingAsk,
    alpha: *const u8,
    sighash: *const u8,
    signature_out: *mut ZsigSaplingSignature,
    rng_callback: ZsigRngCallback,
) -> ZsigError {
    if ask.is_null() || alpha.is_null() || sighash.is_null() || signature_out.is_null() {
        return ZsigError::NullPointer;
    }

    let mut rng = CallbackRng::new(rng_callback);
    let sighash_bytes: [u8; 32] = slice::from_raw_parts(sighash, 32).try_into().unwrap();
    let ask_bytes = (*ask).bytes;
    let alpha_bytes: [u8; 32] = slice::from_raw_parts(alpha, 32).try_into().unwrap();

    // Parse both scalars (Jubjub field)
    let ask_opt = JubjubScalar::from_bytes(&ask_bytes);
    let ask_scalar: JubjubScalar = match Option::<JubjubScalar>::from(ask_opt) {
        Some(s) => s,
        None => return ZsigError::ScalarConversionFailed,
    };

    let alpha_opt = JubjubScalar::from_bytes(&alpha_bytes);
    let alpha_scalar: JubjubScalar = match Option::<JubjubScalar>::from(alpha_opt) {
        Some(s) => s,
        None => return ZsigError::ScalarConversionFailed,
    };

    // Compute randomized signing key: ask + alpha (mod r)
    // This is the core PCZT signing operation
    let ask_randomized: JubjubScalar = ask_scalar + alpha_scalar;

    // Convert back to bytes for reddsa SigningKey
    let randomized_bytes: [u8; 32] = ask_randomized.to_bytes();

    // Create SigningKey from randomized bytes
    let sk: reddsa::SigningKey<SaplingSpendAuth> = match reddsa::SigningKey::try_from(randomized_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Sign the sighash
    let sig: reddsa::Signature<SaplingSpendAuth> = sk.sign(&mut rng, &sighash_bytes);

    if rng.has_failed() {
        return ZsigError::RngFailed;
    }

    // Extract signature bytes
    (*signature_out).bytes = sig.into();

    ZsigError::Success
}

/// Sign a message using RedJubjub (non-randomized)
///
/// This is for testing or cases where no randomization is needed.
///
/// # Safety
/// - `ask` must point to a valid ZsigSaplingAsk
/// - `message` must point to `message_len` readable bytes
/// - `signature_out` must point to valid memory for a ZsigSaplingSignature
/// - `rng_callback` must be a valid function pointer for SecRandomCopyBytes
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_sapling(
    ask: *const ZsigSaplingAsk,
    message: *const u8,
    message_len: usize,
    signature_out: *mut ZsigSaplingSignature,
    rng_callback: ZsigRngCallback,
) -> ZsigError {
    if ask.is_null() || message.is_null() || signature_out.is_null() {
        return ZsigError::NullPointer;
    }

    if message_len > MAX_MESSAGE_LEN {
        return ZsigError::BufferTooSmall;
    }

    let mut rng = CallbackRng::new(rng_callback);
    let msg = slice::from_raw_parts(message, message_len);
    let ask_bytes = (*ask).bytes;

    // Create SigningKey from ask bytes
    let sk: reddsa::SigningKey<SaplingSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Sign the message
    let sig: reddsa::Signature<SaplingSpendAuth> = sk.sign(&mut rng, msg);

    if rng.has_failed() {
        return ZsigError::RngFailed;
    }

    // Extract signature bytes
    (*signature_out).bytes = sig.into();

    ZsigError::Success
}

/// Verify a RedJubjub signature (for testing)
///
/// # Safety
/// - `ak` must point to 32 readable bytes (authorization key / verification key)
/// - `message` must point to `message_len` readable bytes
/// - `signature` must point to a valid ZsigSaplingSignature
#[no_mangle]
pub unsafe extern "C" fn zsig_verify_sapling(
    ak: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const ZsigSaplingSignature,
) -> ZsigError {
    if ak.is_null() || message.is_null() || signature.is_null() {
        return ZsigError::NullPointer;
    }

    if message_len > MAX_MESSAGE_LEN {
        return ZsigError::BufferTooSmall;
    }

    let ak_bytes: [u8; 32] = slice::from_raw_parts(ak, 32).try_into().unwrap();
    let msg = slice::from_raw_parts(message, message_len);
    let sig_bytes = (*signature).bytes;

    // Convert bytes to reddsa types
    let vk: reddsa::VerificationKey<SaplingSpendAuth> = match reddsa::VerificationKey::try_from(ak_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    let sig: reddsa::Signature<SaplingSpendAuth> = reddsa::Signature::from(sig_bytes);

    // Verify the signature
    match vk.verify(msg, &sig) {
        Ok(()) => ZsigError::Success,
        Err(_) => ZsigError::InvalidSignature,
    }
}

/// Derive Sapling ak (authorization key) from ask
///
/// ak = ask * G where G is the Sapling SpendAuth basepoint
///
/// # Safety
/// - `ask` must point to a valid ZsigSaplingAsk
/// - `ak_out` must point to 32 writable bytes
#[no_mangle]
pub unsafe extern "C" fn zsig_derive_sapling_ak_from_ask(
    ask: *const ZsigSaplingAsk,
    ak_out: *mut u8,
) -> ZsigError {
    if ask.is_null() || ak_out.is_null() {
        return ZsigError::NullPointer;
    }

    let ask_bytes = (*ask).bytes;

    // Create SigningKey from ask bytes
    let sk: reddsa::SigningKey<SaplingSpendAuth> = match reddsa::SigningKey::try_from(ask_bytes) {
        Ok(k) => k,
        Err(_) => return ZsigError::InvalidKey,
    };

    // Derive verification key (ak)
    let vk: reddsa::VerificationKey<SaplingSpendAuth> = reddsa::VerificationKey::from(&sk);
    let ak_bytes: [u8; 32] = vk.into();

    // Copy to output
    let out_slice = slice::from_raw_parts_mut(ak_out, 32);
    out_slice.copy_from_slice(&ak_bytes);

    ZsigError::Success
}
