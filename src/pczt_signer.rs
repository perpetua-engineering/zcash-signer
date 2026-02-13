//! PCZT (Partially Created Zcash Transaction) signing module.
//!
//! Uses the pczt crate's full `Signer` role to parse PCZT binary,
//! compute the sighash internally, sign all spend types (Orchard/Sapling/
//! transparent), and return signed PCZT bytes.
//!
//! The watch receives PCZT bytes from the phone, signs with locally-held
//! spending keys, and returns the signed PCZT. The sighash is computed
//! from the PCZT data itself — no external sighash parameter needed.

use alloc::vec::Vec;
use core::fmt;

use pczt::roles::signer::Signer;

// Re-export the upstream protocol crates' key types under clearer names.
// "upstream_orchard" is the package rename for the crates.io orchard crate
// (to avoid conflict with the perpetua fork used by debug-tools).
use upstream_orchard::keys::{
    SpendAuthorizingKey as OrchardSpendAuthorizingKey,
    SpendingKey as OrchardSpendingKey,
};
use sapling_crypto::keys::ExpandedSpendingKey as SaplingExpandedSpendingKey;

// -----------------------------------------------------------------------------
// Error Types
// -----------------------------------------------------------------------------

/// Errors that can occur during PCZT signing.
#[derive(Debug)]
pub enum PcztSignError {
    /// Failed to parse the PCZT binary.
    ParseFailed,
    /// Invalid Orchard spending key bytes.
    InvalidOrchardKey,
    /// Invalid Sapling spending key bytes.
    InvalidSaplingKey,
    /// Invalid transparent secret key bytes.
    InvalidTransparentKey,
    /// Orchard signing failed.
    OrchardSignFailed,
    /// Sapling signing failed.
    SaplingSignFailed,
    /// Transparent signing failed.
    TransparentSignFailed,
}

impl fmt::Display for PcztSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseFailed => write!(f, "failed to parse PCZT binary"),
            Self::InvalidOrchardKey => write!(f, "invalid Orchard spending key"),
            Self::InvalidSaplingKey => write!(f, "invalid Sapling spending key"),
            Self::InvalidTransparentKey => write!(f, "invalid transparent secret key"),
            Self::OrchardSignFailed => write!(f, "Orchard signing failed"),
            Self::SaplingSignFailed => write!(f, "Sapling signing failed"),
            Self::TransparentSignFailed => write!(f, "transparent signing failed"),
        }
    }
}

// -----------------------------------------------------------------------------
// Signing Keys
// -----------------------------------------------------------------------------

/// Keys needed for PCZT signing. All fields are optional — only provide
/// keys for protocols that have spends in the PCZT.
pub struct PcztSigningKeys<'a> {
    /// Orchard spending key (32 bytes). Used to derive ask for signing.
    pub orchard_sk: Option<&'a [u8; 32]>,
    /// Sapling spend authorization key "ask" (32-byte scalar on Jubjub).
    /// Internally wrapped in an ExpandedSpendingKey to satisfy the API.
    pub sapling_ask: Option<&'a [u8; 32]>,
    /// Transparent secp256k1 secret key (32 bytes).
    pub transparent_sk: Option<&'a [u8; 32]>,
}

/// Construct a SaplingExpandedSpendingKey from just the ask bytes.
///
/// The full ExpandedSpendingKey is 96 bytes (ask || nsk || ovk), but for
/// signing we only need ask. We pad nsk and ovk with zeros — they're not
/// used during PCZT signing.
fn sapling_esk_from_ask(ask_bytes: &[u8; 32]) -> Result<SaplingExpandedSpendingKey, PcztSignError> {
    let mut esk_bytes = [0u8; 96];
    esk_bytes[..32].copy_from_slice(ask_bytes);
    // nsk = 0 (valid Jubjub scalar), ovk = 0 (arbitrary 32 bytes)
    // Neither is used by sign_sapling — only ask matters.
    SaplingExpandedSpendingKey::from_bytes(&esk_bytes)
        .map_err(|_| PcztSignError::InvalidSaplingKey)
}

// -----------------------------------------------------------------------------
// Main Signing Function
// -----------------------------------------------------------------------------

/// Parse PCZT binary, sign all applicable spend types, and return signed PCZT bytes.
///
/// Uses the full Signer role which computes the sighash internally from the
/// PCZT data. No external sighash parameter is needed.
///
/// # Arguments
/// * `pczt_bytes` - Raw PCZT binary (with PCZT magic header)
/// * `keys` - Signing keys for each protocol
///
/// # Returns
/// Signed PCZT binary bytes, or an error if signing fails.
pub fn sign_pczt(
    pczt_bytes: &[u8],
    keys: &PcztSigningKeys,
) -> Result<Vec<u8>, PcztSignError> {
    // Parse the PCZT binary.
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|_| PcztSignError::ParseFailed)?;

    // Get spend counts before constructing Signer (which takes ownership).
    let orchard_count = pczt.orchard().actions().len();
    let sapling_count = pczt.sapling().spends().len();
    let transparent_count = pczt.transparent().inputs().len();

    // Create the full Signer (computes sighash from PCZT data).
    let mut signer = Signer::new(pczt).map_err(|_| PcztSignError::ParseFailed)?;

    // Sign Orchard spends if we have an Orchard key.
    if let Some(sk_bytes) = keys.orchard_sk {
        let sk = OrchardSpendingKey::from_bytes(*sk_bytes);
        let sk: OrchardSpendingKey =
            Option::from(sk).ok_or(PcztSignError::InvalidOrchardKey)?;
        let ask = OrchardSpendAuthorizingKey::from(&sk);

        for i in 0..orchard_count {
            // sign_orchard returns WrongSpendAuthorizingKey if rk doesn't
            // match — this happens for dummy spends (IO-finalized actions).
            // We skip those silently, just like the low_level_signer checked
            // alpha().is_some().
            match signer.sign_orchard(i, &ask) {
                Ok(()) => {}
                Err(pczt::roles::signer::Error::OrchardSign(
                    upstream_orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => {
                    // Dummy spend or action we don't own — skip.
                }
                Err(_) => return Err(PcztSignError::OrchardSignFailed),
            }
        }
    }

    // Sign Sapling spends if we have a Sapling key.
    if let Some(ask_bytes) = keys.sapling_ask {
        let esk = sapling_esk_from_ask(ask_bytes)?;

        for i in 0..sapling_count {
            match signer.sign_sapling(i, &esk.ask) {
                Ok(()) => {}
                Err(pczt::roles::signer::Error::SaplingSign(
                    sapling_crypto::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => {
                    // Skip spends we don't own.
                }
                Err(_) => return Err(PcztSignError::SaplingSignFailed),
            }
        }
    }

    // Sign transparent inputs if we have a transparent key.
    if let Some(sk_bytes) = keys.transparent_sk {
        let sk = secp256k1::SecretKey::from_slice(sk_bytes)
            .map_err(|_| PcztSignError::InvalidTransparentKey)?;

        for i in 0..transparent_count {
            signer
                .sign_transparent(i, &sk)
                .map_err(|_| PcztSignError::TransparentSignFailed)?;
        }
    }

    // Finalize and serialize.
    let signed_pczt = signer.finish();
    Ok(signed_pczt.serialize())
}

/// Extract summary information from a PCZT for display on the watch before signing.
///
/// Returns the number of Orchard actions, Sapling spends, and transparent inputs.
pub fn pczt_info(pczt_bytes: &[u8]) -> Result<PcztInfo, PcztSignError> {
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|_| PcztSignError::ParseFailed)?;

    Ok(PcztInfo {
        orchard_actions: pczt.orchard().actions().len(),
        sapling_spends: pczt.sapling().spends().len(),
        transparent_inputs: pczt.transparent().inputs().len(),
        transparent_outputs: pczt.transparent().outputs().len(),
    })
}

/// Summary information extracted from a PCZT.
#[derive(Debug)]
pub struct PcztInfo {
    /// Number of Orchard actions (each is a spend + output).
    pub orchard_actions: usize,
    /// Number of Sapling spends.
    pub sapling_spends: usize,
    /// Number of transparent inputs.
    pub transparent_inputs: usize,
    /// Number of transparent outputs.
    pub transparent_outputs: usize,
}

// =============================================================================
// C FFI
// =============================================================================

use core::slice;
use crate::{ZsigError, ZsigRngCallback};

/// PCZT info returned by `zsig_pczt_info`.
#[repr(C)]
pub struct ZsigPcztInfo {
    pub orchard_actions: u32,
    pub sapling_spends: u32,
    pub transparent_inputs: u32,
    pub transparent_outputs: u32,
}

/// Maximum PCZT payload size (1 MB). Anything larger is rejected.
const MAX_PCZT_LEN: usize = 1024 * 1024;

/// Extract summary information from a PCZT binary.
///
/// # Safety
/// - `pczt_data` must point to `pczt_len` readable bytes
/// - `info_out` must point to a valid `ZsigPcztInfo`
#[no_mangle]
pub unsafe extern "C" fn zsig_pczt_info(
    pczt_data: *const u8,
    pczt_len: usize,
    info_out: *mut ZsigPcztInfo,
) -> ZsigError {
    if pczt_data.is_null() || info_out.is_null() {
        return ZsigError::NullPointer;
    }
    if pczt_len == 0 || pczt_len > MAX_PCZT_LEN {
        return ZsigError::BufferTooSmall;
    }

    let pczt_bytes = slice::from_raw_parts(pczt_data, pczt_len);

    match pczt_info(pczt_bytes) {
        Ok(info) => {
            (*info_out).orchard_actions = info.orchard_actions as u32;
            (*info_out).sapling_spends = info.sapling_spends as u32;
            (*info_out).transparent_inputs = info.transparent_inputs as u32;
            (*info_out).transparent_outputs = info.transparent_outputs as u32;
            ZsigError::Success
        }
        Err(_) => ZsigError::PcztParseFailed,
    }
}

/// Sign a PCZT binary with the provided keys.
///
/// The sighash is computed internally from the PCZT data — no external
/// sighash parameter is needed. The `sighash` parameter is accepted for
/// backwards compatibility but is ignored.
///
/// All key pointers are optional — pass NULL to skip signing for that protocol.
/// The signed PCZT is written to `output` and the actual length is written to
/// `output_len_out`. If `output_len` is too small, returns `BufferTooSmall` and
/// writes the required length to `output_len_out`.
///
/// # Safety
/// - `pczt_data` must point to `pczt_len` readable bytes
/// - `sighash` may be NULL (ignored, kept for ABI compatibility)
/// - `orchard_sk` if non-null must point to 32 readable bytes (Orchard spending key)
/// - `sapling_ask` if non-null must point to 32 readable bytes (Sapling ask)
/// - `transparent_sk` if non-null must point to 32 readable bytes (secp256k1 secret key)
/// - `output` must point to `output_len` writable bytes
/// - `output_len_out` must point to a writable `usize`
/// - `rng_callback` is ignored (kept for ABI compatibility)
#[no_mangle]
pub unsafe extern "C" fn zsig_pczt_sign(
    pczt_data: *const u8,
    pczt_len: usize,
    sighash: *const u8,
    orchard_sk: *const u8,
    sapling_ask: *const u8,
    transparent_sk: *const u8,
    output: *mut u8,
    output_len: usize,
    output_len_out: *mut usize,
    _rng_callback: ZsigRngCallback,
) -> ZsigError {
    // sighash and rng_callback are kept for ABI compatibility but ignored.
    let _ = sighash;

    if pczt_data.is_null() || output.is_null() || output_len_out.is_null() {
        return ZsigError::NullPointer;
    }
    if pczt_len == 0 || pczt_len > MAX_PCZT_LEN {
        return ZsigError::BufferTooSmall;
    }

    let pczt_bytes = slice::from_raw_parts(pczt_data, pczt_len);

    // Build optional key references from nullable pointers.
    let orchard_key: Option<[u8; 32]> = if orchard_sk.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(orchard_sk, 32).try_into().unwrap())
    };

    let sapling_key: Option<[u8; 32]> = if sapling_ask.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(sapling_ask, 32).try_into().unwrap())
    };

    let transparent_key: Option<[u8; 32]> = if transparent_sk.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(transparent_sk, 32).try_into().unwrap())
    };

    let keys = PcztSigningKeys {
        orchard_sk: orchard_key.as_ref(),
        sapling_ask: sapling_key.as_ref(),
        transparent_sk: transparent_key.as_ref(),
    };

    let signed = match sign_pczt(pczt_bytes, &keys) {
        Ok(v) => v,
        Err(e) => {
            return match e {
                PcztSignError::ParseFailed => ZsigError::PcztParseFailed,
                PcztSignError::InvalidOrchardKey
                | PcztSignError::InvalidSaplingKey
                | PcztSignError::InvalidTransparentKey => ZsigError::PcztInvalidKey,
                PcztSignError::OrchardSignFailed
                | PcztSignError::SaplingSignFailed
                | PcztSignError::TransparentSignFailed => ZsigError::PcztSignFailed,
            };
        }
    };

    // Write the actual output length so the caller knows what to expect.
    *output_len_out = signed.len();

    if output_len < signed.len() {
        return ZsigError::BufferTooSmall;
    }

    let out_slice = slice::from_raw_parts_mut(output, signed.len());
    out_slice.copy_from_slice(&signed);

    ZsigError::Success
}
