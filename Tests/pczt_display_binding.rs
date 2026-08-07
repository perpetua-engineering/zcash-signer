//! display==signed negative fixtures for the ZEC PCZT path (CR-1485).
//!
//! Every other Cryptograph chain signs through a WalletCore protobuf, so
//! `tools/display_signed/` can enumerate its signing fields and fail closed on
//! an unclassified one. ZEC signs a PCZT through this crate instead, and the
//! property that stands in for that enumeration is behavioural: **mutating any
//! economically-significant PCZT field after the watch fixed its display must
//! change what `pczt_summary` / `pczt_verify` report**, so the watch's
//! comparisons in `ZecSigningHandler` refuse.
//!
//! These tests build a real, parseable transparent PCZT, take a baseline
//! reading, then mutate exactly one field and assert the reading moves. A
//! regression that stopped decoding a field — or started trusting the phone's
//! claim about it — turns the mutation invisible and fails here.
//!
//! Mutations are applied through serde: the `pczt` crate keeps its wire struct
//! fields `pub(crate)`, so the PCZT is round-tripped through `serde_json`,
//! edited by field name, and re-serialized. That is exactly the capability a
//! compromised phone has, and it keeps the fixtures readable as field edits
//! rather than byte offsets.
//!
//! Run with `cargo test --features pczt-signer,std --test pczt_display_binding`
//! (see `make test-zec-display-binding`).

#![cfg(feature = "pczt-signer")]

use pczt::roles::creator::Creator;
use pczt::Pczt;
use serde_json::{json, Value};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::{BranchId, NetworkType};
use zcash_signer::pczt_signer::{pczt_summary, PcztSignError};
use zcash_signer::pczt_verify::{derive_wallet_viewing_keys, pczt_verify, ApprovedTx, WalletViewingKeys};

/// Mainnet ZEC coin type (SLIP-44).
const COIN_TYPE: u32 = 133;
/// ZIP-244 sighash types.
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_NONE: u8 = 0x02;
const SIGHASH_ALL_ANYONECANPAY: u8 = 0x81;

/// What the watch displayed and the user approved.
const APPROVED_AMOUNT: u64 = 100_000;
const APPROVED_FEE: u64 = 10_000;
const INPUT_VALUE: u64 = 200_000;
const CHANGE_VALUE: u64 = INPUT_VALUE - APPROVED_AMOUNT - APPROVED_FEE;

/// Deterministic test seed. Never a real wallet.
const TEST_SEED: [u8; 32] = [7u8; 32];

/// A hash160 that no derivation of [`TEST_SEED`] produces: the attacker.
const FOREIGN_HASH: [u8; 20] = [0xAB; 20];

// -----------------------------------------------------------------------------
// PCZT construction via serde field edits
// -----------------------------------------------------------------------------

fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

fn t_address(hash: [u8; 20]) -> String {
    ZcashAddress::from_transparent_p2pkh(NetworkType::Main, hash).to_string()
}

fn empty_pczt_json() -> Value {
    let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, COIN_TYPE, [0; 32], [0; 32]).build();
    serde_json::to_value(&pczt).expect("empty PCZT is JSON-representable")
}

fn transparent_input_json(value: u64, hash: &[u8; 20], sighash_type: u8) -> Value {
    json!({
        "prevout_txid": vec![0u8; 32],
        "prevout_index": 0,
        "sequence": null,
        "required_time_lock_time": null,
        "required_height_lock_time": null,
        "script_sig": null,
        "value": value,
        "script_pubkey": p2pkh_script(hash),
        "redeem_script": null,
        "partial_signatures": {},
        "sighash_type": sighash_type,
        "bip32_derivation": {},
        "ripemd160_preimages": {},
        "sha256_preimages": {},
        "hash160_preimages": {},
        "hash256_preimages": {},
        "proprietary": {},
    })
}

fn transparent_output_json(value: u64, hash: &[u8; 20], user_address: Option<&str>) -> Value {
    json!({
        "value": value,
        "script_pubkey": p2pkh_script(hash),
        "redeem_script": null,
        "bip32_derivation": {},
        "user_address": user_address,
        "proprietary": {},
    })
}

fn pczt_from_json(value: Value) -> Pczt {
    let pczt: Pczt = serde_json::from_value(value).expect("edited PCZT deserializes");
    // Round-trip through the real wire format so the fixtures exercise
    // `Pczt::parse`, exactly like bytes arriving from the phone.
    Pczt::parse(&pczt.serialize()).expect("edited PCZT re-parses from its wire encoding")
}

/// The keys the watch derives inside the secure boundary, plus the owned
/// hash160 the change output pays.
fn wallet_keys() -> (WalletViewingKeys, [u8; 20]) {
    let keys = derive_wallet_viewing_keys(&TEST_SEED, COIN_TYPE, 0);
    let owned = *keys
        .transparent_p2pkh
        .first()
        .expect("transparent ownership window is non-empty");
    (keys, owned)
}

/// The PCZT the phone *claims* matches the approval: pay `APPROVED_AMOUNT` to
/// `recipient`, return `CHANGE_VALUE` to a wallet-owned address, `APPROVED_FEE`
/// to miners. `edit` then applies the attacker's post-display mutation.
fn build_pczt<F: FnOnce(&mut Value)>(
    recipient_hash: &[u8; 20],
    owned_hash: &[u8; 20],
    edit: F,
) -> Pczt {
    let mut value = empty_pczt_json();
    value["transparent"]["inputs"] = json!([transparent_input_json(
        INPUT_VALUE,
        owned_hash,
        SIGHASH_ALL
    )]);
    value["transparent"]["outputs"] = json!([
        transparent_output_json(APPROVED_AMOUNT, recipient_hash, None),
        transparent_output_json(CHANGE_VALUE, owned_hash, None),
    ]);
    let mut edited = value;
    edit(&mut edited);
    pczt_from_json(edited)
}

fn approved_tx(recipient: &str) -> ApprovedTx<'_> {
    ApprovedTx {
        recipient_address: recipient,
        expected_amount_zatoshis: APPROVED_AMOUNT,
        expected_memo: "",
        network: NetworkType::Main,
    }
}

// -----------------------------------------------------------------------------
// Baseline: the honest PCZT is accepted
// -----------------------------------------------------------------------------

#[test]
fn honest_pczt_decodes_to_the_approved_display() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH; // an external payee, not us
    let recipient = t_address(recipient_hash);
    let pczt = build_pczt(&recipient_hash, &owned, |_| {});
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.recipient_amount_zatoshis, APPROVED_AMOUNT);
    assert_eq!(summary.fee_zatoshis, APPROVED_FEE);
    assert_eq!(summary.matched_outputs, 1);
    assert!(!summary.has_unverified_recipient_amount);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_eq!(verdict.recipient_amount_zatoshis, APPROVED_AMOUNT);
    assert_eq!(verdict.fee_zatoshis, APPROVED_FEE);
    assert_eq!(verdict.recipient_output_count, 1);
    assert_eq!(verdict.foreign_output_count, 0);
    assert!(verdict.all_outputs_accounted);
    assert!(verdict.memo_matches);
}

// -----------------------------------------------------------------------------
// Negative fixtures: one mutated PCZT field each
// -----------------------------------------------------------------------------

#[test]
fn mutated_recipient_amount_is_visible_to_the_watch() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    // The phone displayed APPROVED_AMOUNT, then shrank the recipient output.
    let pczt = build_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][0]["value"] = json!(1u64);
    });
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.recipient_amount_zatoshis, 1);
    assert_ne!(
        summary.recipient_amount_zatoshis, APPROVED_AMOUNT,
        "ZecSigningHandler.verifyPcztSummary refuses on this inequality"
    );

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_ne!(verdict.recipient_amount_zatoshis, APPROVED_AMOUNT);
}

#[test]
fn mutated_recipient_address_is_visible_to_the_watch() {
    let (keys, owned) = wallet_keys();
    let approved_hash = [0x11u8; 20];
    let recipient = t_address(approved_hash);

    // Displayed `recipient`, signed a payment to the attacker instead.
    let pczt = build_pczt(&FOREIGN_HASH, &owned, |_| {});
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(
        summary.matched_outputs, 0,
        "no output pays the approved recipient"
    );
    assert_eq!(summary.recipient_amount_zatoshis, 0);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_eq!(verdict.recipient_output_count, 0);
    assert_eq!(verdict.foreign_output_count, 1);
    assert!(
        !verdict.all_outputs_accounted,
        "the attacker output is neither the recipient nor wallet-owned"
    );
}

#[test]
fn diverted_change_output_is_refused() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = [0x11u8; 20];
    let recipient = t_address(recipient_hash);

    // Recipient output and fee are untouched — only the change is diverted, the
    // exact hole CR-1337's totality check exists to close.
    let pczt = build_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][1]["script_pubkey"] = json!(p2pkh_script(&FOREIGN_HASH));
    });
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(
        summary.recipient_amount_zatoshis, APPROVED_AMOUNT,
        "the summary alone cannot see this mutation"
    );
    assert_eq!(summary.fee_zatoshis, APPROVED_FEE);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_eq!(verdict.foreign_output_count, 1);
    assert!(!verdict.all_outputs_accounted);
}

#[test]
fn mutated_fee_is_visible_to_the_watch() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    // Skim the change into the fee after displaying APPROVED_FEE.
    let pczt = build_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][1]["value"] = json!(1u64);
    });
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_ne!(summary.fee_zatoshis, APPROVED_FEE);
    assert_eq!(summary.fee_zatoshis, INPUT_VALUE - APPROVED_AMOUNT - 1);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_ne!(verdict.fee_zatoshis, APPROVED_FEE);
}

#[test]
fn spoofed_user_address_does_not_stand_in_for_the_script() {
    let (_keys, owned) = wallet_keys();
    let recipient_hash = [0x11u8; 20];
    let recipient = t_address(recipient_hash);

    // Pay the attacker, but label the output with the approved address so a
    // verifier that trusted `user_address` would report a match.
    let pczt = build_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][0]["script_pubkey"] = json!(p2pkh_script(&FOREIGN_HASH));
        value["transparent"]["outputs"][0]["user_address"] = json!(recipient);
    });
    let bytes = pczt.serialize();

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.matched_outputs, 0);
    assert_eq!(summary.recipient_amount_zatoshis, 0);
    assert!(
        summary.has_unverified_recipient_amount,
        "ZecSigningHandler.verifyPcztSummary refuses on this flag"
    );
}

#[test]
fn transparent_input_must_request_sighash_all() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = [0x11u8; 20];
    let recipient = t_address(recipient_hash);

    // A SIGHASH_NONE signature authorises the inputs without committing to any
    // output, so every output check above becomes non-binding. Refuse instead.
    for sighash_type in [SIGHASH_NONE, SIGHASH_ALL_ANYONECANPAY] {
        let pczt = build_pczt(&recipient_hash, &owned, |value| {
            value["transparent"]["inputs"][0]["sighash_type"] = json!(sighash_type);
        });
        let bytes = pczt.serialize();

        match pczt_verify(&bytes, &approved_tx(&recipient), &keys) {
            Err(PcztSignError::UnsupportedSighashType) => {}
            other => panic!(
                "sighash type {sighash_type:#04x} must be refused, got {:?}",
                other.map(|verdict| verdict.all_outputs_accounted)
            ),
        }
    }
}
