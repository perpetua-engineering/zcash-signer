//! PCZT ownership-totality + memo verification (CR-1337).
//!
//! `pczt_summary` (see `pczt_signer.rs`) verifies only the *approved recipient's*
//! output amount and the net fee. That leaves two live display≠signed fund-loss
//! holes:
//!
//!   1. **Change / own-receiver diversion.** A compromised phone can redirect the
//!      change output (or a shielding destination, ZEC-4) to an attacker. The
//!      recipient amount and the net fee are both unchanged, so `pczt_summary`
//!      accepts it and the watch signs — the user silently loses the change.
//!   2. **Net-neutral metadata diversion.** A compromised phone can describe an
//!      undecryptable nonzero Orchard output as `value = 0`, making the action's
//!      committed net value look like a dummy while preserving the visible fee.
//!      We authenticate spent-note values by recomputing their nullifiers with
//!      the wallet FVK, then require those values to conserve against the
//!      PCZT's committed Orchard net value.
//!   3. **Memo display≠signed.** `pczt_summary` never looks at the note memo, so
//!      the phone can display memo X while signing memo Y.
//!
//! Closing these requires the wallet's **viewing keys**, which only exist inside
//! the secure (SE-derived seed) boundary. This module takes the derived viewing
//! keys and enforces *output totality*: every output must be either the approved
//! recipient or provably wallet-owned (Orchard/Sapling IVK membership, or an
//! owned transparent pubkey hash). Any unaccounted/foreign output ⇒ REFUSE. The
//! approved recipient's memo is recovered from the signed note ciphertext and
//! compared to the approved memo.
//!
//! Fail-closed: a missing field, an unparseable address, or an output we cannot
//! account for all resolve to "not owned" ⇒ the verdict refuses signing.

use alloc::vec::Vec;

use alloc::string::{String, ToString};
use upstream_orchard::{
    keys::{
        FullViewingKey as OrchardFullViewingKey, IncomingViewingKey as OrchardIvk,
        OutgoingViewingKey as OrchardOvk, PreparedIncomingViewingKey, Scope,
    },
    note::{ExtractedNoteCommitment, Note as OrchardNote, Nullifier},
    note_encryption::{
        CompactAction, DomainVersion, IronwoodVersion, NoteEncryptionDomain, OrchardVersion,
    },
    value::ValueCommitment as OrchardValueCommitment,
    Address as OrchardAddress,
};
use zcash_note_encryption::{
    try_note_decryption, try_output_recovery_with_ovk, EphemeralKeyBytes, ShieldedOutput,
    ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
};

use sapling_crypto::{
    zip32::DiversifiableFullViewingKey as SaplingDfvk, PaymentAddress as SaplingAddress,
};

use zcash_protocol::consensus::{BranchId, NetworkType};

use crate::pczt_signer::{PcztSignError, RecipientReceivers};

/// How many transparent address indices (each of the external and internal
/// chains) to derive when testing whether a transparent output is wallet-owned.
/// In this wallet, transparent outputs normally appear only as the *recipient*
/// (shielded change is Orchard), so this window is a defensive backstop against
/// any flow that produces transparent change; it is intentionally generous.
pub const TRANSPARENT_OWNERSHIP_WINDOW: u32 = 20;

/// The wallet's viewing keys, derived inside the secure boundary from the seed.
///
/// Each is optional so callers can omit pools the PCZT does not touch, but a
/// `None` for a pool that *does* have outputs means those outputs cannot be
/// proven owned ⇒ they count as foreign (fail-closed).
pub struct WalletViewingKeys {
    pub orchard_fvk: Option<OrchardFullViewingKey>,
    pub sapling_dfvk: Option<SaplingDfvk>,
    /// P2PKH pubkey hashes (hash160) the wallet owns (external + change chains).
    pub transparent_p2pkh: Vec<[u8; 20]>,
}

/// Derive the wallet's viewing keys from a BIP-39 seed at the standard account
/// path (m/.../coin_type'/account'). All key material stays local; only viewing
/// keys (which cannot spend) are retained for the ownership test.
pub fn derive_wallet_viewing_keys(seed: &[u8], coin_type: u32, account: u32) -> WalletViewingKeys {
    // Orchard FVK from the ZIP-32 spending key.
    let orchard_fvk = {
        let sk_bytes = crate::keys::derive_orchard_sk(seed, coin_type, account);
        Option::<upstream_orchard::keys::SpendingKey>::from(
            upstream_orchard::keys::SpendingKey::from_bytes(sk_bytes),
        )
        .map(|sk| OrchardFullViewingKey::from(&sk))
    };

    // Sapling DFVK via sapling-crypto's authoritative ZIP-32 derivation.
    let sapling_dfvk = {
        use sapling_crypto::zip32::ExtendedSpendingKey;
        use zip32::ChildIndex;
        let master = ExtendedSpendingKey::master(seed);
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(coin_type),
            ChildIndex::hardened(account),
        ];
        let xsk = ExtendedSpendingKey::from_path(&master, &path);
        Some(xsk.to_diversifiable_full_viewing_key())
    };

    // Transparent owned pubkey hashes: external + change chains over a window.
    let mut transparent_p2pkh = Vec::new();
    for change in [0u32, 1u32] {
        for index in 0..TRANSPARENT_OWNERSHIP_WINDOW {
            if let Some(hash) = crate::transparent::derive_transparent_p2pkh_hash(
                seed, coin_type, account, change, index,
            ) {
                transparent_p2pkh.push(hash);
            }
        }
    }

    WalletViewingKeys {
        orchard_fvk,
        sapling_dfvk,
        transparent_p2pkh,
    }
}

impl WalletViewingKeys {
    fn orchard_owns(&self, addr: &OrchardAddress) -> bool {
        self.orchard_fvk
            .as_ref()
            .map(|fvk| fvk.scope_for_address(addr).is_some())
            .unwrap_or(false)
    }

    fn sapling_owns(&self, addr: &SaplingAddress) -> bool {
        self.sapling_dfvk
            .as_ref()
            .map(|dfvk| dfvk.decrypt_diversifier(addr).is_some())
            .unwrap_or(false)
    }

    fn transparent_owns(&self, hash: &[u8; 20]) -> bool {
        self.transparent_p2pkh.iter().any(|owned| owned == hash)
    }
}

/// Verdict produced by [`pczt_verify`].
#[derive(Debug, Default)]
pub struct PcztVerdict {
    /// Number of legacy Orchard actions in the signed bytes. With
    /// `ironwood_action_count`, lets the watch display which shielded pools the
    /// transaction touches, derived from the verified bytes (never from
    /// phone-supplied display strings).
    pub orchard_action_count: u32,
    /// Number of Ironwood actions in the signed bytes.
    pub ironwood_action_count: u32,
    /// Publicly revealed net value leaving the legacy Orchard pool (the Orchard
    /// bundle's committed positive value balance), zatoshis. Non-zero only for
    /// post-NU6.3 transactions that publicly cross value out of legacy Orchard
    /// (into Ironwood, transparent, or Sapling); the watch must display this
    /// crossing amount with its source/destination pools before approval.
    pub legacy_orchard_net_outflow_zatoshis: u64,
    /// Total value sent to the approved recipient (across all pools), zatoshis.
    pub recipient_amount_zatoshis: u64,
    /// Total positive value sent to wallet-owned non-recipient outputs, zatoshis.
    /// Shielding PCZTs use this to bind the displayed shield amount to the signed
    /// owned Orchard output, because a redacted shielding output is not an
    /// external recipient payment.
    pub wallet_owned_output_amount_zatoshis: u64,
    /// Net transaction fee, zatoshis.
    pub fee_zatoshis: u64,
    /// Number of outputs paying the approved recipient.
    pub recipient_output_count: u32,
    /// Number of outputs that are neither the recipient nor wallet-owned. Any
    /// value > 0 ⇒ the watch must refuse (diversion / foreign output).
    pub foreign_output_count: u32,
    /// True iff every output is the approved recipient or provably wallet-owned.
    pub all_outputs_accounted: bool,
    /// True iff the recipient output's memo was recovered from the signed
    /// ciphertext and equals the approved memo.
    pub memo_matches: bool,
    /// True iff a memo comparison was actually performed (recipient memo
    /// recoverable). When false the caller decides policy (fail-closed).
    pub memo_checked: bool,
    /// True iff the approved recipient address is itself wallet-owned. For a
    /// shielding (t→z self-send) the watch must require this (ZEC-4): otherwise
    /// a compromised phone can name an attacker UA as both the "recipient" and
    /// the output, which would pass the totality check as a legitimate payment.
    pub recipient_owned: bool,
}

/// A minimal [`ShieldedOutput`] over a PCZT Orchard output's raw ciphertext
/// fields, so we can trial-decrypt / sender-recover without an
/// `orchard::pczt::Action` (which the `pczt` crate keeps `pub(crate)`).
struct OrchardOutputCiphertext {
    epk: EphemeralKeyBytes,
    cmx: [u8; 32],
    enc: [u8; ENC_CIPHERTEXT_SIZE],
}

impl<V: DomainVersion> ShieldedOutput<NoteEncryptionDomain<V>, { ENC_CIPHERTEXT_SIZE }>
    for OrchardOutputCiphertext
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk.0)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc
    }
}

/// Approved transaction parameters the watch is asked to sign, against which the
/// signed bytes are checked.
pub struct ApprovedTx<'a> {
    pub recipient_address: &'a str,
    pub expected_amount_zatoshis: u64,
    /// The approved memo as shown to the user (canonical text form; empty == no
    /// memo). Compared against the memo recovered from the recipient note.
    pub expected_memo: &'a str,
    pub network: NetworkType,
}

/// True iff this network upgrade carries the Ironwood pool and v6 transactions
/// (NU6.3 and later). `BranchId` is zcash_protocol's exhaustive exact-ID
/// registry: an unrecognized wire branch ID never reaches this function.
fn branch_supports_ironwood(branch: BranchId) -> bool {
    // Explicit per-upgrade match (not ordering): historical branches keep their
    // exact behavior, and a future upgrade added to zcash_protocol must be
    // classified here deliberately before the watch will sign under it.
    match branch {
        BranchId::Nu6_3 => true,
        _ => false,
    }
}

/// Verify output totality and memo binding for a PCZT against the approved tx,
/// using the wallet's viewing keys. Never panics; fail-closed on any decode gap.
pub fn pczt_verify(
    pczt_bytes: &[u8],
    approved: &ApprovedTx,
    keys: &WalletViewingKeys,
) -> Result<PcztVerdict, PcztSignError> {
    let mut pczt = pczt::Pczt::parse(pczt_bytes).map_err(|_| PcztSignError::ParseFailed)?;
    // Resolve derived/compact field representations (absent cv_net, absent cmx,
    // memo-plaintext enc ciphertexts) once up front. Anything unresolvable
    // fails closed here, before any display fact is derived from the bytes.
    pczt.resolve_fields()
        .map_err(|_| PcztSignError::ParseFailed)?;
    let pczt = pczt;
    let recipient = RecipientReceivers::parse(approved.recipient_address, approved.network)?;

    // CR-1485: everything below proves things about the PCZT's *output set*.
    // That proof is worthless for a transparent input whose signature does not
    // commit to the outputs, so require SIGHASH_ALL before doing the work.
    // (Same check runs in `sign_pczt` so the signature itself cannot be unbound.)
    crate::pczt_signer::enforce_sighash_all(&pczt)?;

    // Exact-ID branch resolution. Unknown or unsupported consensus branch IDs
    // refuse before any pool is interpreted (CR-1499).
    let branch = BranchId::try_from(*pczt.global().consensus_branch_id())
        .map_err(|_| PcztSignError::ParseFailed)?;
    let ironwood_era = branch_supports_ironwood(branch);
    // A pre-NU6.3 transaction cannot carry Ironwood data. The pczt crate keeps
    // the v5 Ironwood slot canonically empty; refuse any value-bearing leak
    // instead of silently ignoring actions the user would never see.
    if !ironwood_era
        && (!pczt.ironwood().actions().is_empty()
            || *pczt.ironwood().value_sum() != (0, false)
            || pczt.ironwood().anchor().is_some())
    {
        return Err(PcztSignError::ParseFailed);
    }

    let fee = compute_fee(&pczt)?;

    // ZEC-4: is the approved recipient itself one of our addresses? A shielding
    // self-send requires this; the watch enforces it for shielding flows.
    let recipient_owned = recipient
        .orchard
        .as_ref()
        .and_then(|raw| Option::<OrchardAddress>::from(OrchardAddress::from_raw_address_bytes(raw)))
        .map(|a| keys.orchard_owns(&a))
        .unwrap_or(false)
        || recipient
            .sapling
            .as_ref()
            .and_then(SaplingAddress::from_bytes)
            .map(|a| keys.sapling_owns(&a))
            .unwrap_or(false)
        || recipient
            .p2pkh
            .as_ref()
            .map(|h| keys.transparent_owns(h))
            .unwrap_or(false);

    let mut verdict = PcztVerdict {
        fee_zatoshis: fee,
        all_outputs_accounted: true,
        recipient_owned,
        memo_matches: true,
        memo_checked: approved.expected_memo.is_empty(),
        orchard_action_count: u32::try_from(pczt.orchard().actions().len())
            .map_err(|_| PcztSignError::SummaryOverflow)?,
        ironwood_action_count: u32::try_from(pczt.ironwood().actions().len())
            .map_err(|_| PcztSignError::SummaryOverflow)?,
        ..PcztVerdict::default()
    };

    let mut amount: u128 = 0;
    let mut wallet_owned_output_amount: u128 = 0;
    let orchard_ivks = keys.orchard_prepared_ivks();
    let orchard_ovks = keys.orchard_ovks();

    // ── Transparent outputs ────────────────────────────────────────────────
    for output in pczt.transparent().outputs() {
        let script = output.script_pubkey();
        if recipient.matches_transparent_script(script) {
            amount = amount
                .checked_add(u128::from(*output.value()))
                .ok_or(PcztSignError::SummaryOverflow)?;
            verdict.recipient_output_count = verdict.recipient_output_count.saturating_add(1);
            continue;
        }
        // Zero-value transparent outputs can't divert funds.
        if *output.value() == 0 {
            continue;
        }
        match p2pkh_hash(script) {
            Some(hash) if keys.transparent_owns(&hash) => {
                wallet_owned_output_amount = wallet_owned_output_amount
                    .checked_add(u128::from(*output.value()))
                    .ok_or(PcztSignError::SummaryOverflow)?;
            }
            _ => {
                verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
                verdict.all_outputs_accounted = false;
            }
        }
    }

    // ── Sapling outputs ────────────────────────────────────────────────────
    for output in pczt.sapling().outputs() {
        let is_recipient = match (output.recipient(), output.value()) {
            (Some(raw), Some(value)) if recipient.sapling.as_ref() == Some(raw) => {
                amount = amount
                    .checked_add(u128::from(*value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
                verdict.recipient_output_count = verdict.recipient_output_count.saturating_add(1);
                true
            }
            _ => false,
        };
        if is_recipient {
            // Sapling output memos are encrypted too, but this verifier does not
            // yet recover them. Refuse Sapling recipients rather than signing an
            // unbound display-vs-signed memo.
            verdict.memo_checked = false;
            verdict.memo_matches = false;
            continue;
        }
        // Zero-value outputs can't divert funds (see the Orchard note); only
        // positive-value non-owned outputs are flagged.
        let has_positive_value = (*output.value()).map(|v| v > 0).unwrap_or(true);
        if !has_positive_value {
            continue;
        }
        let owned = output
            .recipient()
            .as_ref()
            .and_then(SaplingAddress::from_bytes)
            .map(|addr| keys.sapling_owns(&addr))
            .unwrap_or(false);
        if !owned {
            verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
            verdict.all_outputs_accounted = false;
        } else if let Some(value) = *output.value() {
            wallet_owned_output_amount = wallet_owned_output_amount
                .checked_add(u128::from(value))
                .ok_or(PcztSignError::SummaryOverflow)?;
        }
    }

    // ── Orchard-protocol pools (legacy Orchard + Ironwood) ─────────────────
    //
    // Both bundles share the Orchard action structure; they differ in note
    // plaintext version (V2 vs V3) and in what post-NU6.3 consensus permits:
    // no new value may enter legacy Orchard, so in the Ironwood era every
    // positive-value legacy Orchard output — including one paying the approved
    // recipient — is a diversion and refuses. Payments to Orchard-protocol
    // receivers land in the Ironwood bundle instead.
    let mut scan = OrchardPoolScanState {
        amount,
        wallet_owned_output_amount,
        recipient_receiver: recipient.orchard,
        approved_memo: approved.expected_memo,
    };

    let legacy_allows_new_value = !ironwood_era;
    scan_orchard_protocol_pool::<OrchardVersion>(
        &pczt,
        OrchardProtocolPool::Orchard,
        legacy_allows_new_value,
        keys,
        &orchard_ivks,
        &orchard_ovks,
        &mut scan,
        &mut verdict,
    )?;
    if ironwood_era {
        scan_orchard_protocol_pool::<IronwoodVersion>(
            &pczt,
            OrchardProtocolPool::Ironwood,
            true,
            keys,
            &orchard_ivks,
            &orchard_ovks,
            &mut scan,
            &mut verdict,
        )?;

        // Publicly revealed value leaving legacy Orchard (pool crossing). The
        // committed value balance is a signed consensus field, so this amount is
        // bound to the signed bytes, not to any phone-supplied description.
        let committed_orchard_net = signed_orchard_value_sum(*pczt.orchard().value_sum())?;
        if committed_orchard_net > 0 {
            verdict.legacy_orchard_net_outflow_zatoshis =
                u64::try_from(committed_orchard_net).map_err(|_| PcztSignError::SummaryOverflow)?;
        }
    }

    amount = scan.amount;
    wallet_owned_output_amount = scan.wallet_owned_output_amount;

    if amount > u128::from(u64::MAX) || wallet_owned_output_amount > u128::from(u64::MAX) {
        return Err(PcztSignError::SummaryOverflow);
    }
    verdict.recipient_amount_zatoshis = amount as u64;
    verdict.wallet_owned_output_amount_zatoshis = wallet_owned_output_amount as u64;
    Ok(verdict)
}

// -----------------------------------------------------------------------------
// Orchard-protocol pool scanning (legacy Orchard + Ironwood)
// -----------------------------------------------------------------------------

/// Which Orchard-protocol pool a scan pass covers.
#[derive(Clone, Copy, PartialEq)]
enum OrchardProtocolPool {
    Orchard,
    Ironwood,
}

impl OrchardProtocolPool {
    fn bundle<'a>(&self, pczt: &'a pczt::Pczt) -> &'a pczt::orchard::Bundle {
        match self {
            Self::Orchard => pczt.orchard(),
            Self::Ironwood => pczt.ironwood(),
        }
    }
}

/// Accumulators shared by the per-pool output scans.
struct OrchardPoolScanState<'a> {
    amount: u128,
    wallet_owned_output_amount: u128,
    /// The approved recipient's Orchard-protocol receiver (identical raw
    /// encoding in both pools).
    recipient_receiver: Option<[u8; 43]>,
    approved_memo: &'a str,
}

/// Scan one Orchard-protocol bundle: classify every output as recipient /
/// wallet-owned / foreign, recover + bind the recipient memo, and enforce value
/// conservation between authenticated spend values and the committed net value.
///
/// `allow_new_value` is false for the legacy Orchard bundle in the Ironwood era
/// (post-NU6.3 no new value may enter legacy Orchard): any positive-value
/// output there — recipient-matching or wallet-owned included — is refused as
/// foreign rather than silently accounted.
#[allow(clippy::too_many_arguments)]
fn scan_orchard_protocol_pool<V: DomainVersion>(
    pczt: &pczt::Pczt,
    pool: OrchardProtocolPool,
    allow_new_value: bool,
    keys: &WalletViewingKeys,
    ivks: &[PreparedIncomingViewingKey],
    ovks: &[OrchardOvk],
    scan: &mut OrchardPoolScanState<'_>,
    verdict: &mut PcztVerdict,
) -> Result<(), PcztSignError> {
    let bundle = pool.bundle(pczt);
    let mut output_value_total: u128 = 0;
    let (spend_value_total, mut conservation_failed) =
        authenticated_orchard_spend_total(pczt, pool, keys)?;

    for action in bundle.actions() {
        let output = action.output();
        let output_value = match output.value() {
            Some(value) => {
                output_value_total = output_value_total
                    .checked_add(u128::from(*value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
                Some(*value)
            }
            None => {
                conservation_failed = true;
                None
            }
        };
        let parsed_addr = output.recipient().as_ref().and_then(|raw| {
            Option::<OrchardAddress>::from(OrchardAddress::from_raw_address_bytes(raw))
        });

        let matches_recipient = matches!(
            (output.recipient(), output_value),
            (Some(raw), Some(_)) if scan.recipient_receiver.as_ref() == Some(raw)
        );

        if matches_recipient {
            if !allow_new_value {
                // Post-NU6.3, a payment to an Orchard-protocol receiver lands
                // in Ironwood. A recipient-paying output in the legacy Orchard
                // bundle is consensus-invalid new value — refuse it instead of
                // counting it toward the approved amount.
                verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
                verdict.all_outputs_accounted = false;
                continue;
            }
            if let Some(value) = output_value {
                scan.amount = scan
                    .amount
                    .checked_add(u128::from(value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
            }
            verdict.recipient_output_count = verdict.recipient_output_count.saturating_add(1);

            // Recover the memo from the signed ciphertext (sender-side, via ock)
            // and bind it to the approved memo. This runs even when the approved
            // memo is empty, so an injected signed memo is refused instead of
            // being treated as "nothing to check".
            match recover_orchard_memo::<V>(action, ovks) {
                Some(memo) => {
                    verdict.memo_checked = true;
                    if canonical_memo(&memo) != scan.approved_memo {
                        verdict.memo_matches = false;
                    }
                }
                None => {
                    verdict.memo_checked = false;
                    verdict.memo_matches = false;
                }
            }
            continue;
        }

        // Not the recipient: must be wallet-owned (change / self). Dummy
        // outputs are represented with value 0, but zero-value metadata is not
        // trusted by itself: when spends are present, the authenticated-spend
        // conservation check below binds those values back to the committed
        // net value.
        let has_positive_value = output_value.map(|v| v > 0).unwrap_or(true);
        if has_positive_value {
            if !allow_new_value {
                // No new value may enter this pool post-NU6.3: even a
                // wallet-owned output here could never be created by consensus
                // — refuse rather than account it.
                verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
                verdict.all_outputs_accounted = false;
                continue;
            }
            let owned = match parsed_addr.as_ref() {
                Some(addr) if keys.orchard_owns(addr) => true,
                // Redacted recipient field: fall back to trial decryption.
                _ => orchard_action_is_ours::<V>(action, ivks),
            };
            if !owned {
                verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
                verdict.all_outputs_accounted = false;
            } else if let Some(value) = output_value {
                scan.wallet_owned_output_amount = scan
                    .wallet_owned_output_amount
                    .checked_add(u128::from(value))
                    .ok_or(PcztSignError::SummaryOverflow)?;
            }
        }
    }

    // Value conservation binds the per-action metadata values to the bundle's
    // committed net value, so a net-neutral "real output described as value 0"
    // diversion cannot survive.
    if !bundle.actions().is_empty() {
        let metadata_net = signed_delta(spend_value_total, output_value_total)?;
        let committed_net = signed_orchard_value_sum(*bundle.value_sum())?;
        if conservation_failed || metadata_net != committed_net {
            verdict.foreign_output_count = verdict.foreign_output_count.saturating_add(1);
            verdict.all_outputs_accounted = false;
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Orchard-protocol trial-decryption helpers
// -----------------------------------------------------------------------------

/// Build the note-encryption domain + ciphertext wrapper for a PCZT action's
/// output. `V` selects the pool's note plaintext version (Orchard V2 or
/// Ironwood V3). Returns `None` if the ciphertext fields are malformed or
/// still compacted (fail-closed).
fn orchard_output_parts<V: DomainVersion>(
    action: &pczt::orchard::Action,
) -> Option<(NoteEncryptionDomain<V>, OrchardOutputCiphertext)> {
    let output = action.output();
    let nf = Option::<Nullifier>::from(Nullifier::from_bytes(action.spend().nullifier()))?;
    let cmx_bytes = (*output.cmx())?;
    let cmx =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx_bytes))?;
    let epk_bytes = *output.ephemeral_key();
    // `resolve_fields` restores memo-plaintext representations to encrypted
    // form; anything still unresolved here cannot be verified — fail closed.
    let enc_vec = match output.enc_ciphertext() {
        pczt::orchard::EncCiphertext::Encrypted(bytes) => bytes,
        pczt::orchard::EncCiphertext::MemoPlaintext(_) => return None,
    };
    if enc_vec.len() != ENC_CIPHERTEXT_SIZE {
        return None;
    }
    let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
    enc.copy_from_slice(enc_vec);

    let mut compact = [0u8; 52];
    compact.copy_from_slice(&enc[..52]);
    let compact_action = CompactAction::from_parts(nf, cmx, EphemeralKeyBytes(epk_bytes), compact);
    let domain = NoteEncryptionDomain::<V>::for_compact_action(&compact_action);
    let wrapper = OrchardOutputCiphertext {
        epk: EphemeralKeyBytes(epk_bytes),
        cmx: cmx_bytes,
        enc,
    };
    Some((domain, wrapper))
}

/// True iff the action's output note decrypts under one of our incoming viewing
/// keys (external or internal/change scope) — i.e. it is wallet-owned.
fn orchard_action_is_ours<V: DomainVersion>(
    action: &pczt::orchard::Action,
    ivks: &[PreparedIncomingViewingKey],
) -> bool {
    let Some((domain, wrapper)) = orchard_output_parts::<V>(action) else {
        return false;
    };
    ivks.iter()
        .any(|ivk| try_note_decryption(&domain, ivk, &wrapper).is_some())
}

fn authenticated_orchard_spend_total(
    pczt: &pczt::Pczt,
    pool: OrchardProtocolPool,
    keys: &WalletViewingKeys,
) -> Result<(u128, bool), PcztSignError> {
    let mut total = 0u128;
    let mut failed = false;

    let verifier = pczt::roles::verifier::Verifier::new(pczt.clone());
    let closure = |bundle: &upstream_orchard::pczt::Bundle| {
        for action in bundle.actions() {
            match authenticated_orchard_spend_value(action, keys) {
                Ok(value) => {
                    total = total
                        .checked_add(u128::from(value))
                        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
                }
                Err(()) => {
                    failed = true;
                }
            }
        }
        Ok::<(), pczt::roles::verifier::OrchardError<()>>(())
    };
    let result = match pool {
        OrchardProtocolPool::Orchard => verifier.with_orchard(closure).map(|_| ()),
        OrchardProtocolPool::Ironwood => verifier.with_ironwood(closure).map(|_| ()),
    };

    if result.is_err() {
        failed = true;
    }

    Ok((total, failed))
}

/// Returns the authenticated Orchard-protocol spend value for this action.
///
/// The value is trusted only after reconstructing the spent note from the PCZT
/// spend fields and recomputing its nullifier with our FVK. This binds the
/// phone-provided spend value to a consensus field that the transaction reveals,
/// closing the net-neutral "real output described as value 0" attack. The
/// spent note's plaintext version comes from the parsed spend itself (legacy
/// Orchard V2 vs Ironwood V3 note commitments differ).
fn authenticated_orchard_spend_value(
    action: &upstream_orchard::pczt::Action,
    keys: &WalletViewingKeys,
) -> Result<u64, ()> {
    let spend = action.spend();
    let Some(value) = *spend.value() else {
        return Err(());
    };
    if value.inner() == 0 {
        return Ok(0);
    }

    let Some(fvk) = keys.orchard_fvk.as_ref() else {
        return Err(());
    };
    let Some(recipient) = *spend.recipient() else {
        return Err(());
    };
    let Some(rho) = *spend.rho() else {
        return Err(());
    };
    let Some(rseed) = *spend.rseed() else {
        return Err(());
    };
    let Some(note) = Option::<OrchardNote>::from(OrchardNote::from_parts(
        recipient,
        value,
        rho,
        rseed,
        *spend.note_version(),
    )) else {
        return Err(());
    };

    if note.nullifier(fvk).to_bytes() != spend.nullifier().to_bytes() {
        return Err(());
    }
    Ok(value.inner())
}

/// Recover the recipient note's memo as the *sender* using our outgoing viewing
/// keys. The Orchard protocol derives the outgoing cipher key from `ovk`, the
/// action's value commitment (`cv_net`), cmx and epk, so we reconstruct `cv`
/// from `cv_net` and try each scope's OVK. Returns the raw 512-byte memo if
/// recovered.
fn recover_orchard_memo<V: DomainVersion>(
    action: &pczt::orchard::Action,
    ovks: &[OrchardOvk],
) -> Option<[u8; 512]> {
    let (domain, wrapper) = orchard_output_parts::<V>(action)?;
    let output = action.output();
    let out_vec = output.out_ciphertext();
    if out_vec.len() != OUT_CIPHERTEXT_SIZE {
        return None;
    }
    let mut out_ct = [0u8; OUT_CIPHERTEXT_SIZE];
    out_ct.copy_from_slice(out_vec);

    let cv_bytes = (*action.cv_net())?;
    let cv = Option::<OrchardValueCommitment>::from(OrchardValueCommitment::from_bytes(&cv_bytes))?;

    for ovk in ovks {
        if let Some((_, _, memo)) =
            try_output_recovery_with_ovk(&domain, ovk, &wrapper, &cv, &out_ct)
        {
            return Some(memo);
        }
    }
    None
}

impl WalletViewingKeys {
    fn orchard_prepared_ivks(&self) -> Vec<PreparedIncomingViewingKey> {
        let mut v = Vec::new();
        if let Some(fvk) = self.orchard_fvk.as_ref() {
            for scope in [Scope::External, Scope::Internal] {
                let ivk: OrchardIvk = fvk.to_ivk(scope);
                v.push(PreparedIncomingViewingKey::new(&ivk));
            }
        }
        v
    }

    fn orchard_ovks(&self) -> Vec<OrchardOvk> {
        let mut v = Vec::new();
        if let Some(fvk) = self.orchard_fvk.as_ref() {
            v.push(fvk.to_ovk(Scope::External));
            v.push(fvk.to_ovk(Scope::Internal));
        }
        v
    }
}

// -----------------------------------------------------------------------------
// Memo canonicalization
// -----------------------------------------------------------------------------

/// Reduce a raw 512-byte Zcash memo field to its canonical text form so it can
/// be compared to the user-approved memo string. Empty / no-memo (0xF6 lead, or
/// all-zero) ⇒ "". Text memos (lead byte ≤ 0xF4) ⇒ UTF-8 with trailing NULs
/// stripped. Anything else (non-UTF-8, reserved leads) ⇒ "" (treated as
/// no displayable memo; a non-empty approved memo then fails to match).
fn canonical_memo(memo: &[u8; 512]) -> String {
    match memo[0] {
        0xF6 => String::new(),
        lead if lead <= 0xF4 => {
            let end = memo
                .iter()
                .rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            core::str::from_utf8(&memo[..end])
                .map(|s| s.to_string())
                .unwrap_or_default()
        }
        _ => String::new(),
    }
}

// -----------------------------------------------------------------------------
// Fee + script helpers (mirror pczt_signer's net-balance fee)
// -----------------------------------------------------------------------------

fn compute_fee(pczt: &pczt::Pczt) -> Result<u64, PcztSignError> {
    let transparent_in = sum_u64(pczt.transparent().inputs().iter().map(|i| *i.value()))?;
    let transparent_out = sum_u64(pczt.transparent().outputs().iter().map(|o| *o.value()))?;
    let transparent_balance = transparent_in
        .checked_sub(transparent_out)
        .ok_or(PcztSignError::SummaryOverflow)?;

    let orchard = signed_orchard_value_sum(*pczt.orchard().value_sum())?;
    let ironwood = signed_orchard_value_sum(*pczt.ironwood().value_sum())?;
    let sapling = *pczt.sapling().value_sum();
    let fee = transparent_balance
        .checked_add(orchard)
        .and_then(|v| v.checked_add(ironwood))
        .and_then(|v| v.checked_add(sapling))
        .ok_or(PcztSignError::SummaryOverflow)?;
    if fee < 0 || fee > i128::from(u64::MAX) {
        return Err(PcztSignError::SummaryUnavailable);
    }
    Ok(fee as u64)
}

fn signed_delta(lhs: u128, rhs: u128) -> Result<i128, PcztSignError> {
    if lhs >= rhs {
        i128::try_from(lhs - rhs).map_err(|_| PcztSignError::SummaryOverflow)
    } else {
        i128::try_from(rhs - lhs)
            .map(|value| -value)
            .map_err(|_| PcztSignError::SummaryOverflow)
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

use core::{slice, str};

/// Verdict struct returned across the FFI boundary.
#[repr(C)]
pub struct ZsigPcztVerdict {
    pub recipient_amount_zatoshis: u64,
    pub wallet_owned_output_amount_zatoshis: u64,
    pub fee_zatoshis: u64,
    /// Publicly revealed net value leaving the legacy Orchard pool (pool
    /// crossing), zatoshis. Non-zero ⇒ the watch must display the crossing
    /// with source/destination pools before approval (CR-1499).
    pub legacy_orchard_net_outflow_zatoshis: u64,
    pub recipient_output_count: u32,
    pub foreign_output_count: u32,
    /// Number of legacy Orchard actions in the signed bytes.
    pub orchard_action_count: u32,
    /// Number of Ironwood actions in the signed bytes.
    pub ironwood_action_count: u32,
    /// 1 iff every output is the approved recipient or wallet-owned.
    pub all_outputs_accounted: bool,
    /// 1 iff the recipient memo was recovered and matched the approved memo.
    pub memo_matches: bool,
    /// 1 iff a memo comparison was performed (recipient memo recoverable).
    pub memo_checked: bool,
    /// 1 iff the approved recipient is itself wallet-owned (ZEC-4: required for
    /// shielding self-sends).
    pub recipient_owned: bool,
}

/// Maximum PCZT payload size (1 MB).
pub(crate) const MAX_PCZT_LEN: usize = 1024 * 1024;
/// Maximum approved-memo length accepted across the FFI (Zcash memo is 512 B).
pub(crate) const MAX_MEMO_LEN: usize = 512;

/// Shared body: parse inputs, build keys via `derive`, run `pczt_verify`, write
/// the verdict. Returns a `ZsigError`.
pub(crate) fn verify_ffi_common(
    pczt_bytes: &[u8],
    recipient: &str,
    expected_amount: u64,
    expected_memo: &str,
    mainnet: bool,
    keys: &WalletViewingKeys,
    out: *mut ZsigPcztVerdict,
) -> crate::ZsigError {
    let network = if mainnet {
        NetworkType::Main
    } else {
        NetworkType::Test
    };
    let approved = ApprovedTx {
        recipient_address: recipient,
        expected_amount_zatoshis: expected_amount,
        expected_memo,
        network,
    };
    match pczt_verify(pczt_bytes, &approved, keys) {
        Ok(verdict) => {
            unsafe {
                (*out).recipient_amount_zatoshis = verdict.recipient_amount_zatoshis;
                (*out).wallet_owned_output_amount_zatoshis =
                    verdict.wallet_owned_output_amount_zatoshis;
                (*out).fee_zatoshis = verdict.fee_zatoshis;
                (*out).legacy_orchard_net_outflow_zatoshis =
                    verdict.legacy_orchard_net_outflow_zatoshis;
                (*out).recipient_output_count = verdict.recipient_output_count;
                (*out).foreign_output_count = verdict.foreign_output_count;
                (*out).orchard_action_count = verdict.orchard_action_count;
                (*out).ironwood_action_count = verdict.ironwood_action_count;
                (*out).all_outputs_accounted = verdict.all_outputs_accounted;
                (*out).memo_matches = verdict.memo_matches;
                (*out).memo_checked = verdict.memo_checked;
                (*out).recipient_owned = verdict.recipient_owned;
            }
            crate::ZsigError::Success
        }
        Err(_) => crate::ZsigError::PcztParseFailed,
    }
}

/// Decode UTF-8 inputs from raw pointers, fail-closed on malformed bytes.
pub(crate) unsafe fn decode_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    str::from_utf8(slice::from_raw_parts(ptr, len)).ok()
}

/// Verify PCZT output totality + memo binding using viewing keys derived from a
/// raw seed. For host/CLI/e2e use (no Secure Enclave). The watch uses the
/// `secure` variant which keeps the seed in C/Rust.
///
/// # Safety
/// - `seed` must point to `seed_len` readable bytes
/// - `pczt_data` must point to `pczt_len` readable bytes
/// - `recipient`/`memo` if non-null point to readable UTF-8 of the given lengths
/// - `out` must point to a writable `ZsigPcztVerdict`
#[no_mangle]
pub unsafe extern "C" fn zsig_pczt_verify(
    seed: *const u8,
    seed_len: usize,
    pczt_data: *const u8,
    pczt_len: usize,
    recipient: *const u8,
    recipient_len: usize,
    expected_amount: u64,
    memo: *const u8,
    memo_len: usize,
    coin_type: u32,
    account: u32,
    mainnet: bool,
    out: *mut ZsigPcztVerdict,
) -> crate::ZsigError {
    if seed.is_null() || pczt_data.is_null() || out.is_null() {
        return crate::ZsigError::NullPointer;
    }
    if seed_len < 32 || seed_len > 252 {
        return crate::ZsigError::InvalidSeed;
    }
    if pczt_len == 0 || pczt_len > MAX_PCZT_LEN {
        return crate::ZsigError::BufferTooSmall;
    }
    if memo_len > MAX_MEMO_LEN {
        return crate::ZsigError::BufferTooSmall;
    }
    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let pczt_bytes = slice::from_raw_parts(pczt_data, pczt_len);
    let Some(recipient_str) = decode_str(recipient, recipient_len) else {
        return crate::ZsigError::PcztParseFailed;
    };
    let Some(memo_str) = decode_str(memo, memo_len) else {
        return crate::ZsigError::PcztParseFailed;
    };
    if recipient_str.is_empty() {
        return crate::ZsigError::PcztParseFailed;
    }

    let keys = derive_wallet_viewing_keys(seed_slice, coin_type, account);
    verify_ffi_common(
        pczt_bytes,
        recipient_str,
        expected_amount,
        memo_str,
        mainnet,
        &keys,
        out,
    )
}

fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(hash);
            Some(out)
        }
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pczt::roles::creator::Creator;
    use zcash_protocol::consensus::BranchId;

    fn empty_pczt() -> alloc::vec::Vec<u8> {
        Creator::new(
            BranchId::Nu6.into(),
            10_000_000,
            133,
            Some([0; 32]),
            Some([0; 32]),
        )
        .expect("creator accepts NU6")
        .build()
        .expect("empty v5 pczt builds")
        .serialize()
        .expect("empty v5 pczt serializes")
    }

    fn empty_v6_pczt() -> alloc::vec::Vec<u8> {
        Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, None, None)
            .expect("creator accepts NU6.3")
            .build()
            .expect("empty v6 pczt builds")
            .serialize()
            .expect("empty v6 pczt serializes")
    }

    #[test]
    fn canonical_memo_no_memo_is_empty() {
        let mut m = [0u8; 512];
        m[0] = 0xF6; // canonical "no memo"
        assert_eq!(canonical_memo(&m), "");
        assert_eq!(canonical_memo(&[0u8; 512]), ""); // all-zero lead ≤ 0xF4, no text
    }

    #[test]
    fn canonical_memo_text_roundtrip() {
        let text = "gm ☕";
        let mut m = [0u8; 512];
        m[..text.len()].copy_from_slice(text.as_bytes());
        assert_eq!(canonical_memo(&m), text);
    }

    #[test]
    fn canonical_memo_reserved_lead_is_empty() {
        let mut m = [0u8; 512];
        m[0] = 0xF5; // reserved (> 0xF4, != 0xF6)
        assert_eq!(canonical_memo(&m), "");
    }

    #[test]
    fn p2pkh_hash_extracts_hash160() {
        let mut script = alloc::vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[0xABu8; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(p2pkh_hash(&script), Some([0xABu8; 20]));
        assert_eq!(p2pkh_hash(&[0x00, 0x01]), None);
    }

    #[test]
    fn verify_rejects_malformed_pczt() {
        let keys = WalletViewingKeys {
            orchard_fvk: None,
            sapling_dfvk: None,
            transparent_p2pkh: alloc::vec::Vec::new(),
        };
        let approved = ApprovedTx {
            recipient_address: "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
            expected_amount_zatoshis: 10_000,
            expected_memo: "",
            network: NetworkType::Main,
        };
        assert!(pczt_verify(b"not a pczt", &approved, &keys).is_err());
    }

    #[test]
    fn verify_empty_pczt_has_no_outputs_and_stays_accounted() {
        // An empty creator PCZT has no outputs: nothing to divert, no recipient
        // output found. Totality holds vacuously; the watch's separate
        // "recipient_output_count > 0" guard is what refuses a no-recipient tx.
        let pczt = empty_pczt();
        let keys = WalletViewingKeys {
            orchard_fvk: None,
            sapling_dfvk: None,
            transparent_p2pkh: alloc::vec::Vec::new(),
        };
        let approved = ApprovedTx {
            recipient_address: "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            expected_amount_zatoshis: 0,
            expected_memo: "",
            network: NetworkType::Main,
        };
        let verdict = pczt_verify(&pczt, &approved, &keys).expect("empty pczt verifies");
        assert_eq!(verdict.recipient_output_count, 0);
        assert_eq!(verdict.foreign_output_count, 0);
        assert!(verdict.all_outputs_accounted);
        assert_eq!(verdict.orchard_action_count, 0);
        assert_eq!(verdict.ironwood_action_count, 0);
        assert_eq!(verdict.legacy_orchard_net_outflow_zatoshis, 0);
    }

    #[test]
    fn verify_empty_v6_pczt_verifies_with_no_crossing() {
        // A v6 (NU6.3) PCZT with empty bundles verifies vacuously: no Ironwood
        // actions, no legacy Orchard outflow, totality holds.
        let pczt = empty_v6_pczt();
        let keys = WalletViewingKeys {
            orchard_fvk: None,
            sapling_dfvk: None,
            transparent_p2pkh: alloc::vec::Vec::new(),
        };
        let approved = ApprovedTx {
            recipient_address: "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            expected_amount_zatoshis: 0,
            expected_memo: "",
            network: NetworkType::Main,
        };
        let verdict = pczt_verify(&pczt, &approved, &keys).expect("empty v6 pczt verifies");
        assert!(verdict.all_outputs_accounted);
        assert_eq!(verdict.ironwood_action_count, 0);
        assert_eq!(verdict.legacy_orchard_net_outflow_zatoshis, 0);
    }

    #[test]
    fn branch_capability_is_exact_per_upgrade() {
        assert!(branch_supports_ironwood(BranchId::Nu6_3));
        assert!(!branch_supports_ironwood(BranchId::Nu6_2));
        assert!(!branch_supports_ironwood(BranchId::Nu5));
    }

    #[test]
    fn derive_wallet_viewing_keys_populates_pools() {
        // A 64-byte test seed must yield an Orchard FVK, a Sapling DFVK, and a
        // non-empty transparent ownership window (no false "no keys").
        let seed = [7u8; 64];
        let keys = derive_wallet_viewing_keys(&seed, 133, 0);
        assert!(keys.orchard_fvk.is_some());
        assert!(keys.sapling_dfvk.is_some());
        assert_eq!(
            keys.transparent_p2pkh.len() as u32,
            2 * TRANSPARENT_OWNERSHIP_WINDOW
        );
    }
}
