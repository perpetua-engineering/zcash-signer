//! PCZT (Partially Created Zcash Transaction) signing module.
//!
//! Uses the pczt crate's `low_level_signer` role to parse PCZT binary,
//! sign all spend types (Orchard/Sapling/transparent), and return signed
//! PCZT bytes.
//!
//! The watch receives PCZT bytes + sighash from the phone, signs with
//! locally-held spending keys, and returns the signed PCZT.

use alloc::vec::Vec;
use core::fmt;

use pczt::roles::low_level_signer::Signer;
use rand_core::{CryptoRng, RngCore};

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
    /// Invalid Sapling expanded spending key bytes.
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
            Self::InvalidSaplingKey => write!(f, "invalid Sapling expanded spending key"),
            Self::InvalidTransparentKey => write!(f, "invalid transparent secret key"),
            Self::OrchardSignFailed => write!(f, "Orchard signing failed"),
            Self::SaplingSignFailed => write!(f, "Sapling signing failed"),
            Self::TransparentSignFailed => write!(f, "transparent signing failed"),
        }
    }
}

// Bridge error type that satisfies the From<ParseError> bounds required by
// the low_level_signer callbacks. Inner values retained for Debug output.
#[derive(Debug)]
#[allow(dead_code)]
enum InternalSignError {
    Orchard(upstream_orchard::pczt::SignerError),
    OrchardParse(upstream_orchard::pczt::ParseError),
    Sapling(sapling_crypto::pczt::SignerError),
    SaplingParse(sapling_crypto::pczt::ParseError),
    Transparent(zcash_transparent::pczt::SignerError),
    TransparentParse(zcash_transparent::pczt::ParseError),
}

impl From<upstream_orchard::pczt::ParseError> for InternalSignError {
    fn from(e: upstream_orchard::pczt::ParseError) -> Self {
        Self::OrchardParse(e)
    }
}

impl From<sapling_crypto::pczt::ParseError> for InternalSignError {
    fn from(e: sapling_crypto::pczt::ParseError) -> Self {
        Self::SaplingParse(e)
    }
}

impl From<zcash_transparent::pczt::ParseError> for InternalSignError {
    fn from(e: zcash_transparent::pczt::ParseError) -> Self {
        Self::TransparentParse(e)
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
    /// Sapling expanded spending key (96 bytes: ask || nsk || ovk).
    pub sapling_esk: Option<&'a [u8; 96]>,
    /// Transparent secp256k1 secret key (32 bytes).
    pub transparent_sk: Option<&'a [u8; 32]>,
}

// -----------------------------------------------------------------------------
// Main Signing Function
// -----------------------------------------------------------------------------

/// Parse PCZT binary, sign all applicable spend types, and return signed PCZT bytes.
///
/// # Arguments
/// * `pczt_bytes` - Raw PCZT binary (with PCZT magic header)
/// * `sighash` - 32-byte transaction sighash (computed by the phone)
/// * `keys` - Signing keys for each protocol
/// * `rng` - Cryptographic RNG for signature randomness
///
/// # Returns
/// Signed PCZT binary bytes, or an error if signing fails.
pub fn sign_pczt<R: RngCore + CryptoRng>(
    pczt_bytes: &[u8],
    sighash: [u8; 32],
    keys: &PcztSigningKeys,
    mut rng: R,
) -> Result<Vec<u8>, PcztSignError> {
    // Parse the PCZT binary.
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|_| PcztSignError::ParseFailed)?;

    // Create the low-level signer.
    let mut signer = Signer::new(pczt);

    // Sign Orchard spends if we have an Orchard key.
    if let Some(sk_bytes) = keys.orchard_sk {
        let sk = OrchardSpendingKey::from_bytes(*sk_bytes);
        let sk: OrchardSpendingKey =
            Option::from(sk).ok_or(PcztSignError::InvalidOrchardKey)?;
        let ask = OrchardSpendAuthorizingKey::from(&sk);

        signer = signer
            .sign_orchard_with(
                |_pczt, bundle, _tx_modifiable| -> Result<(), InternalSignError> {
                    for action in bundle.actions_mut() {
                        // Only sign actions that have an alpha (spend authorization
                        // randomizer). Actions without alpha are dummy spends.
                        if action.spend().alpha().is_some() {
                            action
                                .sign(sighash, &ask, &mut rng)
                                .map_err(InternalSignError::Orchard)?;
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|_| PcztSignError::OrchardSignFailed)?;
    }

    // Sign Sapling spends if we have a Sapling key.
    if let Some(esk_bytes) = keys.sapling_esk {
        let esk = SaplingExpandedSpendingKey::from_bytes(esk_bytes)
            .map_err(|_| PcztSignError::InvalidSaplingKey)?;

        signer = signer
            .sign_sapling_with(
                |_pczt, bundle, _tx_modifiable| -> Result<(), InternalSignError> {
                    for spend in bundle.spends_mut() {
                        if spend.alpha().is_some() {
                            spend
                                .sign(sighash, &esk.ask, &mut rng)
                                .map_err(InternalSignError::Sapling)?;
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|_| PcztSignError::SaplingSignFailed)?;
    }

    // Sign transparent inputs if we have a transparent key.
    if let Some(sk_bytes) = keys.transparent_sk {
        let sk = secp256k1::SecretKey::from_slice(sk_bytes)
            .map_err(|_| PcztSignError::InvalidTransparentKey)?;
        let secp = secp256k1::Secp256k1::signing_only();

        signer = signer
            .sign_transparent_with(
                |_pczt, bundle, _tx_modifiable| -> Result<(), InternalSignError> {
                    for (index, input) in bundle.inputs_mut().iter_mut().enumerate() {
                        // For transparent inputs, the sighash computation depends on
                        // the input. In the common SIGHASH_ALL case, the phone
                        // pre-computes and sends one sighash. We pass it through
                        // the closure, ignoring the SignableInput details.
                        input
                            .sign(index, |_signable_input| sighash, &sk, &secp)
                            .map_err(InternalSignError::Transparent)?;
                    }
                    Ok(())
                },
            )
            .map_err(|_| PcztSignError::TransparentSignFailed)?;
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
