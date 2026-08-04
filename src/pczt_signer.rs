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
use core::{convert::Infallible, fmt, str};

use ff::PrimeField;

use pczt::roles::signer::Signer;
use zcash_address::{
    unified::{Container, Receiver},
    ConversionError, TryFromAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

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
    /// Recipient address could not be parsed for summary verification.
    InvalidRecipientAddress,
    /// PCZT values needed for summary verification are unavailable.
    SummaryUnavailable,
    /// PCZT value balance overflowed the verifier's arithmetic.
    SummaryOverflow,
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
            Self::InvalidRecipientAddress => write!(f, "invalid recipient address"),
            Self::SummaryUnavailable => write!(f, "PCZT summary unavailable"),
            Self::SummaryOverflow => write!(f, "PCZT summary overflow"),
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
///
/// CR-1337 (gap 4): we MUST reject a malformed ask here. `sapling-crypto`'s
/// `SpendAuthorizingKey::from_bytes` evaluates `redjubjub::SigningKey::try_from(b)
/// .expect(...)` *eagerly*, before its own `!is_zero()` guard. `redjubjub`
/// rejects the zero scalar (and any non-canonical encoding) that `jubjub`
/// accepts, so a zero/malformed ask drives that `.expect()` to panic — and the
/// device build is `panic = "abort"`, i.e. a crash. Validating the ask is a
/// non-zero canonical Jubjub scalar before we ever hand it to the signer turns
/// that crash into a clean `InvalidSaplingKey`. On the production secure path
/// the ask is SE-derived and always valid, so this never rejects a real key.
///
/// Adversarial-`alpha` note: the re-randomization `rsk = ask.randomize(&alpha)`
/// (with attacker-influenced `alpha` from the PCZT) computes `rsk = ask + alpha`
/// by direct scalar addition and builds the `SigningKey` from the sum WITHOUT
/// the panicking `try_from`/`.expect` path. So a chosen `alpha` cannot reach the
/// malformed-key panic even though it perturbs the signing scalar; the only
/// degenerate sum (`rsk == 0`, i.e. `alpha == -ask`) needs the secret `ask` and
/// merely yields a useless zero key that still signs without aborting. Guarding
/// the base `ask` is therefore sufficient.
fn sapling_esk_from_ask(ask_bytes: &[u8; 32]) -> Result<SaplingExpandedSpendingKey, PcztSignError> {
    // Reject anything redjubjub would reject (non-canonical or zero), fail-closed.
    let scalar = Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(*ask_bytes))
        .ok_or(PcztSignError::InvalidSaplingKey)?;
    if bool::from(ff::Field::is_zero(&scalar)) {
        return Err(PcztSignError::InvalidSaplingKey);
    }

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

/// Extract the recipient amount and transaction fee from a PCZT.
///
/// The watch compares this summary against the approval fields before signing so
/// a compromised phone cannot show benign text while supplying different bytes.
pub fn pczt_summary(
    pczt_bytes: &[u8],
    recipient_address: &str,
    network: NetworkType,
) -> Result<PcztSummary, PcztSignError> {
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|_| PcztSignError::ParseFailed)?;
    let recipient = RecipientReceivers::parse(recipient_address, network)?;

    let transparent_input_total = sum_u64(
        pczt.transparent()
            .inputs()
            .iter()
            .map(|input| *input.value()),
    )?;
    let transparent_output_total = sum_u64(
        pczt.transparent()
            .outputs()
            .iter()
            .map(|output| *output.value()),
    )?;
    let transparent_balance = transparent_input_total
        .checked_sub(transparent_output_total)
        .ok_or(PcztSignError::SummaryOverflow)?;

    let orchard_value_sum = signed_orchard_value_sum(*pczt.orchard().value_sum())?;
    let sapling_value_sum = *pczt.sapling().value_sum();
    let fee = transparent_balance
        .checked_add(orchard_value_sum)
        .and_then(|value| value.checked_add(sapling_value_sum))
        .ok_or(PcztSignError::SummaryOverflow)?;
    if fee < 0 || fee > i128::from(u64::MAX) {
        return Err(PcztSignError::SummaryUnavailable);
    }

    let mut amount: u128 = 0;
    let mut matched_outputs: u32 = 0;
    let mut has_unverified_recipient_amount = false;

    for output in pczt.transparent().outputs() {
        if recipient.matches_transparent_script(output.script_pubkey()) {
            amount = amount
                .checked_add(u128::from(*output.value()))
                .ok_or(PcztSignError::SummaryOverflow)?;
            matched_outputs = matched_outputs
                .checked_add(1)
                .ok_or(PcztSignError::SummaryOverflow)?;
        } else if output.user_address().as_deref() == Some(recipient_address) {
            has_unverified_recipient_amount = true;
        }
    }

    for output in pczt.sapling().outputs() {
        match (output.recipient(), output.value()) {
            (Some(output_recipient), Some(value))
                if recipient.sapling.as_ref() == Some(output_recipient) =>
            {
                amount = amount
                    .checked_add(u128::from(*value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
                matched_outputs = matched_outputs
                    .checked_add(1)
                    .ok_or(PcztSignError::SummaryOverflow)?;
            }
            _ if output.user_address().as_deref() == Some(recipient_address) => {
                has_unverified_recipient_amount = true;
            }
            _ => {}
        }
    }

    for action in pczt.orchard().actions() {
        let output = action.output();
        match (output.recipient(), output.value()) {
            (Some(output_recipient), Some(value))
                if recipient.orchard.as_ref() == Some(output_recipient) =>
            {
                amount = amount
                    .checked_add(u128::from(*value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
                matched_outputs = matched_outputs
                    .checked_add(1)
                    .ok_or(PcztSignError::SummaryOverflow)?;
            }
            _ if output.user_address().as_deref() == Some(recipient_address) => {
                has_unverified_recipient_amount = true;
            }
            _ => {}
        }
    }

    if amount > u128::from(u64::MAX) {
        return Err(PcztSignError::SummaryOverflow);
    }

    Ok(PcztSummary {
        recipient_amount_zatoshis: amount as u64,
        fee_zatoshis: fee as u64,
        matched_outputs,
        transparent_outputs: pczt.transparent().outputs().len() as u32,
        sapling_outputs: pczt.sapling().outputs().len() as u32,
        orchard_outputs: pczt.orchard().actions().len() as u32,
        has_unverified_recipient_amount,
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

/// PCZT-derived summary fields used for display-vs-bytes verification.
#[derive(Debug)]
pub struct PcztSummary {
    pub recipient_amount_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub matched_outputs: u32,
    pub transparent_outputs: u32,
    pub sapling_outputs: u32,
    pub orchard_outputs: u32,
    pub has_unverified_recipient_amount: bool,
}

#[derive(Default)]
pub(crate) struct RecipientReceivers {
    pub(crate) p2pkh: Option<[u8; 20]>,
    pub(crate) p2sh: Option<[u8; 20]>,
    pub(crate) sapling: Option<[u8; 43]>,
    pub(crate) orchard: Option<[u8; 43]>,
}

impl RecipientReceivers {
    pub(crate) fn parse(encoded: &str, network: NetworkType) -> Result<Self, PcztSignError> {
        ZcashAddress::try_from_encoded(encoded)
            .map_err(|_| PcztSignError::InvalidRecipientAddress)?
            .convert_if_network(network)
            .map_err(|_| PcztSignError::InvalidRecipientAddress)
    }

    pub(crate) fn matches_transparent_script(&self, script: &[u8]) -> bool {
        match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
                self.p2pkh.as_ref().is_some_and(|expected| expected == hash)
            }
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
                self.p2sh.as_ref().is_some_and(|expected| expected == hash)
            }
            _ => false,
        }
    }
}

impl TryFromAddress for RecipientReceivers {
    type Error = Infallible;

    fn try_from_sapling(
        _net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self {
            sapling: Some(data),
            ..Self::default()
        })
    }

    fn try_from_unified(
        _net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let mut receivers = Self::default();
        for receiver in data.items() {
            match receiver {
                Receiver::Orchard(bytes) => receivers.orchard = Some(bytes),
                Receiver::Sapling(bytes) => receivers.sapling = Some(bytes),
                Receiver::P2pkh(bytes) => receivers.p2pkh = Some(bytes),
                Receiver::P2sh(bytes) => receivers.p2sh = Some(bytes),
                Receiver::Unknown { .. } => {}
            }
        }
        Ok(receivers)
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self {
            p2pkh: Some(data),
            ..Self::default()
        })
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self {
            p2sh: Some(data),
            ..Self::default()
        })
    }

    fn try_from_tex(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self {
            p2pkh: Some(data),
            ..Self::default()
        })
    }
}

fn sum_u64(mut values: impl Iterator<Item = u64>) -> Result<i128, PcztSignError> {
    values.try_fold(0i128, |sum, value| {
        sum.checked_add(i128::from(value))
            .ok_or(PcztSignError::SummaryOverflow)
    })
}

fn signed_orchard_value_sum(value_sum: (u64, bool)) -> Result<i128, PcztSignError> {
    let magnitude = i128::from(value_sum.0);
    if value_sum.1 {
        magnitude
            .checked_neg()
            .ok_or(PcztSignError::SummaryOverflow)
    } else {
        Ok(magnitude)
    }
}

// =============================================================================
// C FFI
// =============================================================================

use core::slice;
use crate::ZsigError;

/// PCZT info returned by `zsig_pczt_info`.
#[repr(C)]
pub struct ZsigPcztInfo {
    pub orchard_actions: u32,
    pub sapling_spends: u32,
    pub transparent_inputs: u32,
    pub transparent_outputs: u32,
}

/// PCZT summary returned by `zsig_pczt_summary`.
#[repr(C)]
pub struct ZsigPcztSummary {
    pub recipient_amount_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub matched_outputs: u32,
    pub transparent_outputs: u32,
    pub sapling_outputs: u32,
    pub orchard_outputs: u32,
    pub has_unverified_recipient_amount: bool,
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

/// Extract recipient amount and fee information from a PCZT binary.
///
/// # Safety
/// - `pczt_data` must point to `pczt_len` readable bytes
/// - `recipient_address` must point to `recipient_address_len` readable UTF-8 bytes
/// - `summary_out` must point to a valid `ZsigPcztSummary`
#[no_mangle]
pub unsafe extern "C" fn zsig_pczt_summary(
    pczt_data: *const u8,
    pczt_len: usize,
    recipient_address: *const u8,
    recipient_address_len: usize,
    mainnet: bool,
    summary_out: *mut ZsigPcztSummary,
) -> ZsigError {
    if pczt_data.is_null() || summary_out.is_null() {
        return ZsigError::NullPointer;
    }
    if recipient_address_len > 0 && recipient_address.is_null() {
        return ZsigError::NullPointer;
    }
    if pczt_len == 0 || pczt_len > MAX_PCZT_LEN {
        return ZsigError::BufferTooSmall;
    }

    let pczt_bytes = slice::from_raw_parts(pczt_data, pczt_len);
    let recipient_bytes = slice::from_raw_parts(recipient_address, recipient_address_len);
    let recipient = match str::from_utf8(recipient_bytes) {
        Ok(value) if !value.is_empty() => value,
        _ => return ZsigError::PcztParseFailed,
    };
    let network = if mainnet {
        NetworkType::Main
    } else {
        NetworkType::Test
    };

    match pczt_summary(pczt_bytes, recipient, network) {
        Ok(summary) => {
            (*summary_out).recipient_amount_zatoshis = summary.recipient_amount_zatoshis;
            (*summary_out).fee_zatoshis = summary.fee_zatoshis;
            (*summary_out).matched_outputs = summary.matched_outputs;
            (*summary_out).transparent_outputs = summary.transparent_outputs;
            (*summary_out).sapling_outputs = summary.sapling_outputs;
            (*summary_out).orchard_outputs = summary.orchard_outputs;
            (*summary_out).has_unverified_recipient_amount =
                summary.has_unverified_recipient_amount;
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
///
/// # RNG contract (CR-1465)
/// Signature randomness comes from upstream `pczt`'s `Signer::sign_sapling` /
/// `sign_orchard`, which use `rand_core::OsRng`. The pinned getrandom backend
/// per target is verified against the built artifact by
/// `tools/build/pczt_rng_verify.py`. A CSPRNG failure is fatal: `OsRng`
/// panics on OS RNG failure and release builds are `panic = "abort"`, so no
/// partial or zero-filled signature can ever be returned.
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
) -> ZsigError {
    // sighash is kept for ABI compatibility but ignored (computed internally).
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
                | PcztSignError::TransparentSignFailed
                | PcztSignError::InvalidRecipientAddress
                | PcztSignError::SummaryUnavailable
                | PcztSignError::SummaryOverflow => ZsigError::PcztSignFailed,
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
