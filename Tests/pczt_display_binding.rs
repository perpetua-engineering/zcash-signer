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
//! fields `pub(crate)`, so the PCZT is round-tripped through `serde_json` via
//! the public `pczt::v1::Pczt` / `pczt::v2::Pczt` serialization types (pczt
//! 0.8 removed serde from the logical types), edited by field name, and
//! re-serialized. That is exactly the capability a compromised phone has, and
//! it keeps the fixtures readable as field edits rather than byte offsets.
//!
//! NU6.3 (CR-1499): the fixtures run against both a v5 (NU6.2-era) PCZT and a
//! v6 (NU6.3) PCZT, which additionally carries the Ironwood bundle. v6-only
//! fixtures cover the Ironwood value balance (fee binding), Ironwood data
//! leaking into pre-NU6.3 transactions, malformed Ironwood actions, and
//! unknown consensus branch IDs.
//!
//! Run with `cargo test --features pczt-signer,std --test pczt_display_binding`
//! (see `make test-zec-display-binding`).

#![cfg(feature = "pczt-signer")]

use ff::PrimeField;
use pczt::roles::creator::Creator;
use pczt::Pczt;
use rand_core::{OsRng, RngCore};
use sapling_crypto::{
    builder::{Builder as SaplingBuilder, BundleType as SaplingBundleType},
    note_encryption::Zip212Enforcement,
    value::NoteValue as SaplingNoteValue,
    Anchor as SaplingAnchor, CommitmentTree as SaplingCommitmentTree,
    IncrementalWitness as SaplingIncrementalWitness, Node as SaplingNode, Note as SaplingNote,
    Rseed as SaplingRseed,
};
use serde_json::{json, Value};
use upstream_orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::{BundleVersion, TxVersion},
    keys::{FullViewingKey as OrchardFullViewingKey, Scope},
    note::{Note as OrchardNote, NoteVersion, RandomSeed, Rho},
    value::{NoteValue, Sign},
};
use zcash_address::{
    unified::{Address as UnifiedAddress, Encoding, Receiver},
    ToAddress, ZcashAddress,
};
use zcash_protocol::consensus::{BranchId, NetworkType};
use zcash_signer::pczt_signer::{pczt_summary, sign_pczt, PcztSignError, PcztSigningKeys};
use zcash_signer::pczt_verify::{
    derive_wallet_viewing_keys, pczt_verify, ApprovedTx, WalletViewingKeys,
};

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
    let pczt = Creator::new(
        BranchId::Nu6.into(),
        10_000_000,
        COIN_TYPE,
        Some([0; 32]),
        Some([0; 32]),
    )
    .expect("creator accepts NU6")
    .build()
    .expect("empty v5 PCZT builds");
    let v1 = pczt::v1::Pczt::try_from(pczt).expect("v5 PCZT has a v1 encoding");
    serde_json::to_value(&v1).expect("empty PCZT is JSON-representable")
}

fn empty_v6_pczt_json() -> Value {
    let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, COIN_TYPE, None, None)
        .expect("creator accepts NU6.3")
        .build()
        .expect("empty v6 PCZT builds");
    let v2 = pczt::v2::Pczt::try_from(pczt).expect("v6 PCZT has a v2 encoding");
    serde_json::to_value(&v2).expect("empty v6 PCZT is JSON-representable")
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
    let v1: pczt::v1::Pczt = serde_json::from_value(value).expect("edited PCZT deserializes");
    // Round-trip through the real wire format so the fixtures exercise
    // `Pczt::parse`, exactly like bytes arriving from the phone.
    Pczt::parse(&v1.serialize()).expect("edited PCZT re-parses from its wire encoding")
}

fn pczt_from_v6_json(value: Value) -> Pczt {
    let v2: pczt::v2::Pczt = serde_json::from_value(value).expect("edited v6 PCZT deserializes");
    Pczt::parse(&v2.serialize()).expect("edited v6 PCZT re-parses from its wire encoding")
}

/// Serialize a logical PCZT to its wire bytes (fallible in pczt 0.8).
fn wire(pczt: Pczt) -> Vec<u8> {
    pczt.serialize().expect("PCZT serializes")
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

/// Create a real wallet-owned legacy-Orchard note for a post-NU6.3 PCZT.
/// The verifier authenticates its value by recomputing the nullifier from the
/// same FVK, so a serde-only placeholder cannot stand in for this fixture.
fn legacy_orchard_note(
    fvk: &OrchardFullViewingKey,
    value: u64,
    bundle_version: BundleVersion,
    rng: &mut impl RngCore,
) -> OrchardNote {
    let rho = loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&bytes)) {
            break rho;
        }
    };
    let rseed = loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho)) {
            break rseed;
        }
    };
    Option::<OrchardNote>::from(OrchardNote::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(value),
        rho,
        rseed,
        bundle_version.note_version(),
    ))
    .expect("test note is internally valid")
}

/// Convert a bundle built by the authoritative Orchard constructor into the
/// public PCZT v2 serde shape used by these display-binding fixtures.
fn orchard_protocol_bundle_json(bundle: &upstream_orchard::pczt::Bundle) -> Value {
    let actions = bundle
        .actions()
        .iter()
        .map(|action| {
            let spend = action.spend();
            let output = action.output();
            let spend_auth_sig = spend.spend_auth_sig().as_ref().map(|signature| {
                let bytes: [u8; 64] = signature.into();
                bytes.to_vec()
            });
            let rk: [u8; 32] = spend.rk().into();

            json!({
                "cv_net": action.cv_net().to_bytes(),
                "spend": {
                    "nullifier": spend.nullifier().to_bytes(),
                    "rk": rk,
                    "spend_auth_sig": spend_auth_sig,
                    "recipient": spend.recipient().as_ref().map(|a| a.to_raw_address_bytes().to_vec()),
                    "value": spend.value().as_ref().map(|v| v.inner()),
                    "rho": spend.rho().as_ref().map(|rho| rho.to_bytes()),
                    "rseed": spend.rseed().as_ref().map(|rseed| *rseed.as_bytes()),
                    "fvk": spend.fvk().as_ref().map(|fvk| fvk.to_bytes().to_vec()),
                    "witness": null,
                    "alpha": spend.alpha().as_ref().map(|alpha| alpha.to_repr()),
                    "zip32_derivation": null,
                    "dummy_sk": spend.dummy_sk().as_ref().map(|sk| *sk.to_bytes()),
                    "proprietary": spend.proprietary().clone(),
                },
                "output": {
                    "cmx": output.cmx().to_bytes(),
                    "ephemeral_key": output.encrypted_note().epk_bytes,
                    "enc_ciphertext": {"Encrypted": output.encrypted_note().enc_ciphertext.to_vec()},
                    "out_ciphertext": output.encrypted_note().out_ciphertext.to_vec(),
                    "recipient": output.recipient().as_ref().map(|a| a.to_raw_address_bytes().to_vec()),
                    "value": output.value().as_ref().map(|v| v.inner()),
                    "rseed": output.rseed().as_ref().map(|rseed| *rseed.as_bytes()),
                    "ock": null,
                    "zip32_derivation": null,
                    "user_address": null,
                    "proprietary": output.proprietary().clone(),
                },
                "rcv": action.rcv().as_ref().map(|rcv| rcv.to_bytes()),
            })
        })
        .collect::<Vec<_>>();
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let bsk: Option<[u8; 32]> = bundle.bsk().as_ref().map(Into::into);

    let note_version = match bundle.bundle_version().note_version() {
        NoteVersion::V2 => "V2",
        NoteVersion::V3 => "V3",
    };

    json!({
        "actions": actions,
        "flags": bundle.flag_byte(),
        "value_sum": (magnitude, matches!(sign, Sign::Negative)),
        "anchor": null,
        "note_version": note_version,
        "zkproof": null,
        "bsk": bsk,
    })
}

/// Build the CR-1507 production shape: a real Legacy Orchard spend, a
/// wallet-owned Legacy Orchard change output, and value leaving the pool for a
/// transparent receiver. `change_fvk` lets the negative fixture divert change.
fn legacy_orchard_unshield_bundle_json(
    spend_fvk: &OrchardFullViewingKey,
    change_fvk: &OrchardFullViewingKey,
) -> Value {
    let mut rng = OsRng;
    let bundle_version = BundleVersion::orchard_v3();
    let note = legacy_orchard_note(spend_fvk, INPUT_VALUE, bundle_version, &mut rng);
    let mut builder = OrchardBuilder::new_with_anchor_deferred(
        BundleType::DEFAULT,
        bundle_version,
        bundle_version.default_flags(),
        TxVersion::V6,
    )
    .expect("post-NU6.3 Orchard supports deferred anchors");
    builder
        .add_spend_unwitnessed(spend_fvk.clone(), note)
        .expect("wallet note is spendable");
    builder
        .add_change_output(
            change_fvk.clone(),
            Some(change_fvk.to_ovk(Scope::Internal)),
            change_fvk.address_at(0u32, Scope::Internal),
            NoteValue::from_raw(CHANGE_VALUE),
            [0u8; 512],
        )
        .expect("wallet-owned legacy Orchard change is constructible");
    let (mut bundle, _) = builder
        .build_for_pczt(&mut rng)
        .expect("legacy Orchard PCZT bundle builds");
    bundle
        .finalize_io([0u8; 32], &mut rng)
        .expect("dummy actions finalize");
    orchard_protocol_bundle_json(&bundle)
}

/// Build a net-neutral legacy-Orchard bundle that spends a real wallet note
/// and sends the entire value to a foreign wallet. This is economically hidden
/// from the transparent cover payment because the committed pool balance is 0.
fn orchard_protocol_net_neutral_drain_bundle_json(
    spend_fvk: &OrchardFullViewingKey,
    foreign_fvk: &OrchardFullViewingKey,
    value: u64,
    bundle_version: BundleVersion,
    memo: [u8; 512],
) -> Value {
    let mut rng = OsRng;
    let note = legacy_orchard_note(spend_fvk, value, bundle_version, &mut rng);
    let mut builder = OrchardBuilder::new_with_anchor_deferred(
        BundleType::DEFAULT,
        bundle_version,
        bundle_version.default_flags(),
        TxVersion::V6,
    )
    .expect("post-NU6.3 Orchard supports deferred anchors");
    builder
        .add_spend_unwitnessed(spend_fvk.clone(), note)
        .expect("wallet note is spendable");
    builder
        .add_change_output(
            foreign_fvk.clone(),
            Some(spend_fvk.to_ovk(Scope::External)),
            foreign_fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            memo,
        )
        .expect("foreign drain output is constructible");
    let (mut bundle, _) = builder
        .build_for_pczt(&mut rng)
        .expect("legacy Orchard PCZT bundle builds");
    bundle
        .finalize_io([0u8; 32], &mut rng)
        .expect("dummy actions finalize");
    orchard_protocol_bundle_json(&bundle)
}

/// Convert an authoritative Sapling PCZT bundle into the public PCZT serde
/// shape used by the mutation fixtures below.
fn sapling_bundle_json(bundle: &sapling_crypto::pczt::Bundle) -> Value {
    let spends = bundle
        .spends()
        .iter()
        .map(|spend| {
            let (rcm, rseed) = match spend.rseed() {
                Some(SaplingRseed::BeforeZip212(rcm)) => (Some(rcm.to_bytes()), None),
                Some(SaplingRseed::AfterZip212(rseed)) => (None, Some(*rseed)),
                None => (None, None),
            };
            let rk: [u8; 32] = (*spend.rk()).into();
            let spend_auth_sig = spend.spend_auth_sig().map(|signature| {
                let bytes: [u8; 64] = signature.into();
                bytes.to_vec()
            });
            let proof_generation_key = spend
                .proof_generation_key()
                .as_ref()
                .map(|key| json!([key.ak.to_bytes(), key.nsk.to_bytes()]));
            let witness = spend.witness().as_ref().map(|witness| {
                json!([
                    u32::try_from(u64::from(witness.position()))
                        .expect("Sapling positions fit in u32"),
                    witness
                        .path_elems()
                        .iter()
                        .map(|node| node.to_bytes())
                        .collect::<Vec<_>>()
                ])
            });

            json!({
                "cv": spend.cv().to_bytes(),
                "nullifier": spend.nullifier().0,
                "rk": rk,
                "zkproof": spend.zkproof().as_ref().map(|proof| proof.to_vec()),
                "spend_auth_sig": spend_auth_sig,
                "recipient": spend
                    .recipient()
                    .map(|recipient| recipient.to_bytes().to_vec()),
                "value": spend.value().map(|value| value.inner()),
                "rcm": rcm,
                "rseed": rseed,
                "rcv": spend.rcv().as_ref().map(|rcv| rcv.inner().to_bytes()),
                "proof_generation_key": proof_generation_key,
                "witness": witness,
                "alpha": spend.alpha().map(|alpha| alpha.to_bytes()),
                "zip32_derivation": null,
                "dummy_ask": spend.dummy_ask().as_ref().map(|ask| ask.to_bytes()),
                "proprietary": spend.proprietary().clone(),
            })
        })
        .collect::<Vec<_>>();
    let outputs = bundle
        .outputs()
        .iter()
        .map(|output| {
            json!({
                "cv": output.cv().to_bytes(),
                "cmu": output.cmu().to_bytes(),
                "ephemeral_key": output.ephemeral_key().0,
                "enc_ciphertext": output.enc_ciphertext().to_vec(),
                "out_ciphertext": output.out_ciphertext().to_vec(),
                "zkproof": output.zkproof().as_ref().map(|proof| proof.to_vec()),
                "recipient": output
                    .recipient()
                    .map(|recipient| recipient.to_bytes().to_vec()),
                "value": output.value().map(|value| value.inner()),
                "rseed": *output.rseed(),
                "rcv": output.rcv().as_ref().map(|rcv| rcv.inner().to_bytes()),
                "ock": output.ock().as_ref().map(|ock| ock.0),
                "zip32_derivation": null,
                "user_address": output.user_address().clone(),
                "proprietary": output.proprietary().clone(),
            })
        })
        .collect::<Vec<_>>();
    let bsk: Option<[u8; 32]> = bundle.bsk().map(|bsk| bsk.into());

    json!({
        "spends": spends,
        "outputs": outputs,
        "value_sum": bundle.value_sum().to_raw(),
        "anchor": bundle.anchor().to_bytes(),
        "bsk": bsk,
    })
}

/// Build the Sapling counterpart of the net-neutral drain: spend a real wallet
/// note and send the entire value to a foreign Sapling address.
fn sapling_net_neutral_drain_bundle_json(
    spend_dfvk: &sapling_crypto::zip32::DiversifiableFullViewingKey,
    foreign_dfvk: &sapling_crypto::zip32::DiversifiableFullViewingKey,
    value: u64,
) -> Value {
    let mut rng = OsRng;
    let spend_recipient = spend_dfvk.default_address().1;
    let note = SaplingNote::from_parts(
        spend_recipient,
        SaplingNoteValue::from_raw(value),
        SaplingRseed::AfterZip212([0x42; 32]),
    );
    let leaf = SaplingNode::from_cmu(&note.cmu());
    let mut tree = SaplingCommitmentTree::empty();
    tree.append(leaf).expect("Sapling note enters test tree");
    let witness = SaplingIncrementalWitness::from_tree(tree).expect("non-empty Sapling tree");
    let anchor = SaplingAnchor::from(witness.root());
    let path = witness.path().expect("Sapling witness has a path");

    let mut builder =
        SaplingBuilder::new(Zip212Enforcement::On, SaplingBundleType::DEFAULT, anchor);
    builder
        .add_spend(spend_dfvk.fvk().clone(), note, path)
        .expect("wallet Sapling note is spendable");
    builder
        .add_output(
            None,
            foreign_dfvk.default_address().1,
            SaplingNoteValue::from_raw(value),
            [0u8; 512],
        )
        .expect("foreign Sapling drain output is constructible");
    let (bundle, _) = builder
        .build_for_pczt(&mut rng)
        .expect("Sapling PCZT bundle builds");
    sapling_bundle_json(&bundle)
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
    value["transparent"]["inputs"] =
        json!([transparent_input_json(INPUT_VALUE, owned_hash, SIGHASH_ALL)]);
    value["transparent"]["outputs"] = json!([
        transparent_output_json(APPROVED_AMOUNT, recipient_hash, None),
        transparent_output_json(CHANGE_VALUE, owned_hash, None),
    ]);
    let mut edited = value;
    edit(&mut edited);
    pczt_from_json(edited)
}

/// The v6 (NU6.3) counterpart of [`build_pczt`]: same transparent payment
/// shape, but the transaction carries the v6 format and an (empty) Ironwood
/// bundle that `edit` can populate.
fn build_v6_pczt<F: FnOnce(&mut Value)>(
    recipient_hash: &[u8; 20],
    owned_hash: &[u8; 20],
    edit: F,
) -> Pczt {
    let mut value = empty_v6_pczt_json();
    // The v2 encoding omits the empty transparent bundle; install it whole.
    value["transparent"] = json!({
        "inputs": [transparent_input_json(INPUT_VALUE, owned_hash, SIGHASH_ALL)],
        "outputs": [
            transparent_output_json(APPROVED_AMOUNT, recipient_hash, None),
            transparent_output_json(CHANGE_VALUE, owned_hash, None),
        ],
    });
    let mut edited = value;
    edit(&mut edited);
    pczt_from_v6_json(edited)
}

/// An Ironwood bundle (v2 serde encoding) with no actions and the given
/// committed value balance.
fn ironwood_bundle_json(value_sum: (u64, bool)) -> Value {
    json!({
        "actions": [],
        "flags": 0b0000_0111,
        "value_sum": value_sum,
        "anchor": null,
        "note_version": "V3",
        "zkproof": null,
        "bsk": null,
    })
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
    let bytes = wire(pczt);

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
    let bytes = wire(pczt);

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
    let bytes = wire(pczt);

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
    let bytes = wire(pczt);

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

/// CR-1507: Legacy Orchard spend to the wallet's transparent receiver, with
/// wallet-owned change retained in the Legacy Orchard bundle.
///
/// This is the production shape that the old verifier rejected. The real
/// Orchard action is load-bearing: restoring the pre-fix blanket rejection of
/// positive Legacy Orchard outputs must fail this test.
#[test]
fn legacy_orchard_unshield_to_wallet_transparent_receiver_is_fully_accounted() {
    let (keys, owned) = wallet_keys();
    let recipient = t_address(owned);
    let spend_fvk = keys.orchard_fvk.as_ref().expect("wallet has Orchard FVK");
    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [],
        "outputs": [transparent_output_json(APPROVED_AMOUNT, &owned, None)],
    });
    value["orchard"] = legacy_orchard_unshield_bundle_json(spend_fvk, spend_fvk);
    let bytes = wire(pczt_from_v6_json(value));

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.matched_outputs, 1);
    assert_eq!(summary.recipient_amount_zatoshis, APPROVED_AMOUNT);
    assert_eq!(summary.fee_zatoshis, APPROVED_FEE);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_eq!(verdict.foreign_output_count, 0);
    assert!(
        verdict.all_outputs_accounted,
        "wallet-owned Legacy Orchard change must not classify as foreign"
    );
    assert_eq!(verdict.recipient_output_count, 1);
    assert_eq!(verdict.wallet_owned_output_amount_zatoshis, CHANGE_VALUE);
    assert_eq!(
        verdict.legacy_orchard_net_outflow_zatoshis,
        APPROVED_AMOUNT + APPROVED_FEE
    );
    assert!(verdict.orchard_action_count > 0);
}

/// The matching negative fixture: a valid Legacy Orchard spend whose retained
/// output belongs to another wallet must still remove approval controls.
#[test]
fn legacy_orchard_unshield_with_foreign_change_is_refused() {
    let (keys, owned) = wallet_keys();
    let recipient = t_address(owned);
    let spend_fvk = keys.orchard_fvk.as_ref().expect("wallet has Orchard FVK");
    let foreign_keys = derive_wallet_viewing_keys(&[8u8; 32], COIN_TYPE, 0);
    let foreign_fvk = foreign_keys
        .orchard_fvk
        .as_ref()
        .expect("foreign wallet has Orchard FVK");
    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [],
        "outputs": [transparent_output_json(APPROVED_AMOUNT, &owned, None)],
    });
    value["orchard"] = legacy_orchard_unshield_bundle_json(spend_fvk, foreign_fvk);
    let bytes = wire(pczt_from_v6_json(value));

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert!(verdict.foreign_output_count > 0);
    assert!(!verdict.all_outputs_accounted);
}

#[test]
fn zeroed_value_metadata_cannot_hide_foreign_orchard_output() {
    const DRAIN: u64 = 500_000;

    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);
    let spend_fvk = keys.orchard_fvk.as_ref().expect("wallet has Orchard FVK");
    let foreign_keys = derive_wallet_viewing_keys(&[8u8; 32], COIN_TYPE, 0);
    let foreign_fvk = foreign_keys
        .orchard_fvk
        .as_ref()
        .expect("foreign wallet has Orchard FVK");

    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [transparent_input_json(INPUT_VALUE, &owned, SIGHASH_ALL)],
        "outputs": [
            transparent_output_json(APPROVED_AMOUNT, &recipient_hash, None),
            transparent_output_json(CHANGE_VALUE, &owned, None),
        ],
    });
    let drain = orchard_protocol_net_neutral_drain_bundle_json(
        spend_fvk,
        foreign_fvk,
        DRAIN,
        BundleVersion::orchard_v3(),
        [0u8; 512],
    );
    assert_eq!(drain["value_sum"], json!((0u64, false)));

    value["orchard"] = drain.clone();
    let honest_bytes = wire(pczt_from_v6_json(value.clone()));
    let honest = pczt_verify(&honest_bytes, &approved_tx(&recipient), &keys)
        .expect("honest foreign drain parses");
    assert!(!honest.all_outputs_accounted);
    assert!(honest.foreign_output_count > 0);
    let no_keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    };
    assert!(
        sign_pczt(&honest_bytes, &no_keys).is_ok(),
        "authentic Orchard metadata must pass the signing-boundary guard"
    );

    let mut zeroed = drain;
    for action in zeroed["actions"]
        .as_array_mut()
        .expect("Orchard actions are an array")
    {
        action["spend"]["value"] = json!(0u64);
        action["output"]["value"] = json!(0u64);
    }
    value["orchard"] = zeroed;
    let attack_bytes = wire(pczt_from_v6_json(value));
    let attack = pczt_verify(&attack_bytes, &approved_tx(&recipient), &keys)
        .expect("zeroed-metadata attack parses");

    assert!(
        !attack.all_outputs_accounted || attack.foreign_output_count > 0,
        "zeroed Orchard metadata must not hide a foreign net-neutral drain"
    );
    assert!(
        matches!(
            sign_pczt(&attack_bytes, &no_keys),
            Err(PcztSignError::UnverifiedShieldedMetadata)
        ),
        "the signing boundary must independently reject zeroed Orchard metadata"
    );
}

#[test]
fn zeroed_value_metadata_cannot_hide_foreign_sapling_output() {
    const DRAIN: u64 = 500_000;

    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);
    let spend_dfvk = keys.sapling_dfvk.as_ref().expect("wallet has Sapling DFVK");
    let foreign_keys = derive_wallet_viewing_keys(&[8u8; 32], COIN_TYPE, 0);
    let foreign_dfvk = foreign_keys
        .sapling_dfvk
        .as_ref()
        .expect("foreign wallet has Sapling DFVK");

    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [transparent_input_json(INPUT_VALUE, &owned, SIGHASH_ALL)],
        "outputs": [
            transparent_output_json(APPROVED_AMOUNT, &recipient_hash, None),
            transparent_output_json(CHANGE_VALUE, &owned, None),
        ],
    });
    let drain = sapling_net_neutral_drain_bundle_json(spend_dfvk, foreign_dfvk, DRAIN);
    assert_eq!(drain["value_sum"], json!(0));

    value["sapling"] = drain.clone();
    let honest_bytes = wire(pczt_from_v6_json(value.clone()));
    let honest = pczt_verify(&honest_bytes, &approved_tx(&recipient), &keys)
        .expect("honest foreign Sapling drain parses");
    assert!(!honest.all_outputs_accounted);
    assert!(honest.foreign_output_count > 0);
    let no_keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    };
    assert!(
        sign_pczt(&honest_bytes, &no_keys).is_ok(),
        "authentic Sapling metadata must pass the signing-boundary guard"
    );

    let mut zeroed = drain;
    for spend in zeroed["spends"]
        .as_array_mut()
        .expect("Sapling spends are an array")
    {
        spend["value"] = json!(0u64);
    }
    for output in zeroed["outputs"]
        .as_array_mut()
        .expect("Sapling outputs are an array")
    {
        output["value"] = json!(0u64);
    }
    value["sapling"] = zeroed;
    let attack_bytes = wire(pczt_from_v6_json(value));
    let attack = pczt_verify(&attack_bytes, &approved_tx(&recipient), &keys)
        .expect("zeroed Sapling-metadata attack parses");

    assert!(
        !attack.all_outputs_accounted || attack.foreign_output_count > 0,
        "zeroed Sapling metadata must not hide a foreign net-neutral drain"
    );
    assert!(
        matches!(
            sign_pczt(&attack_bytes, &no_keys),
            Err(PcztSignError::UnverifiedShieldedMetadata)
        ),
        "the signing boundary must independently reject zeroed Sapling metadata"
    );
}

#[test]
fn zeroed_value_metadata_cannot_hide_foreign_ironwood_output() {
    const DRAIN: u64 = 500_000;

    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);
    let spend_fvk = keys.orchard_fvk.as_ref().expect("wallet has Orchard FVK");
    let foreign_keys = derive_wallet_viewing_keys(&[8u8; 32], COIN_TYPE, 0);
    let foreign_fvk = foreign_keys
        .orchard_fvk
        .as_ref()
        .expect("foreign wallet has Orchard FVK");

    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [transparent_input_json(INPUT_VALUE, &owned, SIGHASH_ALL)],
        "outputs": [
            transparent_output_json(APPROVED_AMOUNT, &recipient_hash, None),
            transparent_output_json(CHANGE_VALUE, &owned, None),
        ],
    });
    let drain = orchard_protocol_net_neutral_drain_bundle_json(
        spend_fvk,
        foreign_fvk,
        DRAIN,
        BundleVersion::ironwood_v3(),
        [0u8; 512],
    );
    assert_eq!(drain["value_sum"], json!((0u64, false)));

    value["ironwood"] = drain.clone();
    let honest_bytes = wire(pczt_from_v6_json(value.clone()));
    let honest = pczt_verify(&honest_bytes, &approved_tx(&recipient), &keys)
        .expect("honest foreign Ironwood drain parses");
    assert!(!honest.all_outputs_accounted);
    assert!(honest.foreign_output_count > 0);
    let no_keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    };
    assert!(
        sign_pczt(&honest_bytes, &no_keys).is_ok(),
        "authentic Ironwood metadata must pass the signing-boundary guard"
    );

    let mut zeroed = drain;
    for action in zeroed["actions"]
        .as_array_mut()
        .expect("Ironwood actions are an array")
    {
        action["spend"]["value"] = json!(0u64);
        action["output"]["value"] = json!(0u64);
    }
    value["ironwood"] = zeroed;
    let attack_bytes = wire(pczt_from_v6_json(value));
    let attack = pczt_verify(&attack_bytes, &approved_tx(&recipient), &keys)
        .expect("zeroed Ironwood-metadata attack parses");

    assert!(
        !attack.all_outputs_accounted || attack.foreign_output_count > 0,
        "zeroed Ironwood metadata must not hide a foreign net-neutral drain"
    );
    assert!(
        matches!(
            sign_pczt(&attack_bytes, &no_keys),
            Err(PcztSignError::UnverifiedShieldedMetadata)
        ),
        "the signing boundary must independently reject zeroed Ironwood metadata"
    );
}

#[test]
fn non_text_orchard_recipient_memo_is_refused() {
    const PAYMENT: u64 = 500_000;

    let (keys, _) = wallet_keys();
    let spend_fvk = keys.orchard_fvk.as_ref().expect("wallet has Orchard FVK");
    let recipient_keys = derive_wallet_viewing_keys(&[8u8; 32], COIN_TYPE, 0);
    let recipient_fvk = recipient_keys
        .orchard_fvk
        .as_ref()
        .expect("recipient wallet has Orchard FVK");
    let recipient_receiver = recipient_fvk
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    let recipient = UnifiedAddress::try_from_items(vec![Receiver::Orchard(recipient_receiver)])
        .expect("single-Orchard-receiver UA is valid")
        .encode(&NetworkType::Main);

    let mut opaque_memo = [0u8; 512];
    opaque_memo[0] = 0xFF;
    opaque_memo[1] = 0x42;

    let mut value = empty_v6_pczt_json();
    value["ironwood"] = orchard_protocol_net_neutral_drain_bundle_json(
        spend_fvk,
        recipient_fvk,
        PAYMENT,
        BundleVersion::ironwood_v3(),
        opaque_memo,
    );
    let bytes = wire(pczt_from_v6_json(value));

    let verdict =
        pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("opaque-memo payment parses");
    assert_eq!(verdict.recipient_amount_zatoshis, PAYMENT);
    assert_eq!(verdict.foreign_output_count, 0);
    assert!(verdict.all_outputs_accounted);
    assert!(verdict.memo_checked);
    assert!(
        !verdict.memo_matches,
        "arbitrary memo bytes must not be treated as the approved empty memo"
    );
}

/// CR-1507: post-NU6.3 Orchard turnstile — value must not *enter* legacy Orchard.
/// A committed negative Orchard value balance is refuse-closed even with no actions.
#[test]
fn nu63_orchard_inflow_is_refused_by_turnstile() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        // Inject a non-empty Orchard value_sum claiming net *inflow* into legacy
        // Orchard (magnitude, is_negative=true). Empty actions skip conservation;
        // the turnstile still sees the committed balance.
        value["orchard"] = json!({
            "actions": [],
            "flags": 0b0000_0111,
            "value_sum": (5_000u64, true),
            "anchor": null,
            "note_version": "V2",
            "zkproof": null,
            "bsk": null,
        });
    });
    let bytes = wire(pczt);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert!(
        !verdict.all_outputs_accounted || verdict.foreign_output_count > 0,
        "Orchard net inflow post-NU6.3 must fail closed"
    );
}

/// CR-1507 negative: a foreign transparent output still removes approval.
#[test]
fn foreign_output_still_fails_closed_on_v6() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = [0x11u8; 20];
    let recipient = t_address(recipient_hash);

    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][1]["script_pubkey"] = json!(p2pkh_script(&FOREIGN_HASH));
    });
    let bytes = wire(pczt);

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
    let bytes = wire(pczt);

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
    let bytes = wire(pczt);

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
    // Keys are unused: enforce_sighash_all runs before any key material is
    // touched. Empty keys prove the refuse is in the signer path itself, not
    // a side effect of a later sign failure.
    let empty_signing_keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    };

    // A SIGHASH_NONE signature authorises the inputs without committing to any
    // output, so every output check above becomes non-binding. Refuse instead
    // — both at verify (before display) and at sign (so the signature itself
    // cannot be unbound if verify is bypassed).
    for sighash_type in [SIGHASH_NONE, SIGHASH_ALL_ANYONECANPAY] {
        let pczt = build_pczt(&recipient_hash, &owned, |value| {
            value["transparent"]["inputs"][0]["sighash_type"] = json!(sighash_type);
        });
        let bytes = wire(pczt);

        match pczt_verify(&bytes, &approved_tx(&recipient), &keys) {
            Err(PcztSignError::UnsupportedSighashType) => {}
            other => panic!(
                "pczt_verify: sighash type {sighash_type:#04x} must be refused, got {:?}",
                other.map(|verdict| verdict.all_outputs_accounted)
            ),
        }

        match sign_pczt(&bytes, &empty_signing_keys) {
            Err(PcztSignError::UnsupportedSighashType) => {}
            other => panic!(
                "sign_pczt: sighash type {sighash_type:#04x} must be refused, got {:?}",
                other.map(|signed| signed.len())
            ),
        }
    }
}

// -----------------------------------------------------------------------------
// NU6.3 / v6 / Ironwood fixtures (CR-1499)
// -----------------------------------------------------------------------------

#[test]
fn honest_v6_pczt_decodes_to_the_approved_display() {
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);
    let pczt = build_v6_pczt(&recipient_hash, &owned, |_| {});
    let bytes = wire(pczt);

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.recipient_amount_zatoshis, APPROVED_AMOUNT);
    assert_eq!(summary.fee_zatoshis, APPROVED_FEE);
    assert_eq!(summary.matched_outputs, 1);
    assert_eq!(summary.ironwood_outputs, 0);

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_eq!(verdict.recipient_amount_zatoshis, APPROVED_AMOUNT);
    assert_eq!(verdict.fee_zatoshis, APPROVED_FEE);
    assert!(verdict.all_outputs_accounted);
    assert_eq!(verdict.ironwood_action_count, 0);
    assert_eq!(verdict.legacy_orchard_net_outflow_zatoshis, 0);
}

#[test]
fn v6_transparent_mutations_remain_visible_to_the_watch() {
    // The five v5 mutations re-run under the v6 transaction format: the decode
    // path (v2 serialization, Ironwood-carrying global) must not weaken any
    // existing binding.
    let (keys, owned) = wallet_keys();
    let recipient_hash = [0x11u8; 20];
    let recipient = t_address(recipient_hash);

    // Shrunk recipient amount.
    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][0]["value"] = json!(1u64);
    });
    let verdict = pczt_verify(&wire(pczt), &approved_tx(&recipient), &keys).expect("verdict");
    assert_ne!(verdict.recipient_amount_zatoshis, APPROVED_AMOUNT);

    // Diverted change.
    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][1]["script_pubkey"] = json!(p2pkh_script(&FOREIGN_HASH));
    });
    let verdict = pczt_verify(&wire(pczt), &approved_tx(&recipient), &keys).expect("verdict");
    assert!(!verdict.all_outputs_accounted);

    // Skimmed fee.
    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["transparent"]["outputs"][1]["value"] = json!(1u64);
    });
    let verdict = pczt_verify(&wire(pczt), &approved_tx(&recipient), &keys).expect("verdict");
    assert_ne!(verdict.fee_zatoshis, APPROVED_FEE);

    // Non-SIGHASH_ALL input.
    for sighash_type in [SIGHASH_NONE, SIGHASH_ALL_ANYONECANPAY] {
        let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
            value["transparent"]["inputs"][0]["sighash_type"] = json!(sighash_type);
        });
        assert!(matches!(
            pczt_verify(&wire(pczt), &approved_tx(&recipient), &keys),
            Err(PcztSignError::UnsupportedSighashType)
        ));
    }
}

#[test]
fn v6_expiry_height_mutation_is_visible_to_the_watch() {
    // Expiry is consequential approval data: changing it after the watch fixed
    // its display must change the byte-derived verdict shown before approval.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    let baseline = build_v6_pczt(&recipient_hash, &owned, |_| {});
    let baseline_verdict =
        pczt_verify(&wire(baseline), &approved_tx(&recipient), &keys).expect("baseline verdict");

    let mutated = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["global"]["expiry_height"] = json!(9_999_999u32);
    });
    let mutated_verdict =
        pczt_verify(&wire(mutated), &approved_tx(&recipient), &keys).expect("mutated verdict");

    assert_eq!(baseline_verdict.expiry_height, 10_000_000);
    assert_eq!(mutated_verdict.expiry_height, 9_999_999);
    assert_ne!(
        baseline_verdict.expiry_height,
        mutated_verdict.expiry_height
    );
}

#[test]
fn ironwood_value_sum_mutation_shifts_the_fee() {
    // The Ironwood bundle's committed value balance participates in the fee
    // equation. A phone that injects a positive Ironwood balance (value quietly
    // leaving the shielded pool) after display must move the fee the watch
    // compares against the approval.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["ironwood"] = ironwood_bundle_json((5_000, false));
    });
    let bytes = wire(pczt);

    let summary = pczt_summary(&bytes, &recipient, NetworkType::Main).expect("summary");
    assert_eq!(summary.fee_zatoshis, APPROVED_FEE + 5_000);
    assert_ne!(
        summary.fee_zatoshis, APPROVED_FEE,
        "ZecSigningHandler.verifyPcztSummary refuses on this inequality"
    );

    let verdict = pczt_verify(&bytes, &approved_tx(&recipient), &keys).expect("verdict");
    assert_ne!(verdict.fee_zatoshis, APPROVED_FEE);
}

#[test]
fn negative_ironwood_value_sum_fails_closed() {
    // A negative Ironwood balance (value entering the pool) that pushes the
    // fee negative must refuse outright, not wrap or display a bogus fee.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
        value["ironwood"] = ironwood_bundle_json((1_000_000, true));
    });
    let bytes = wire(pczt);

    assert!(pczt_summary(&bytes, &recipient, NetworkType::Main).is_err());
    assert!(pczt_verify(&bytes, &approved_tx(&recipient), &keys).is_err());
}

#[test]
fn ironwood_data_in_pre_nu6_3_transaction_is_refused() {
    // A v5 (NU6.2) transaction cannot carry Ironwood value. A v2-encoded PCZT
    // that smuggles a non-canonical Ironwood bundle under a v5 global must be
    // refused before display, not silently ignored.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    // Build the v5 fixture, then re-encode as v2 with an injected Ironwood
    // balance (the capability a compromised phone has).
    let v5 = build_pczt(&recipient_hash, &owned, |_| {});
    let v2 = pczt::v2::Pczt::try_from(v5).expect("v5 PCZT has a v2 encoding");
    let mut value = serde_json::to_value(&v2).expect("v2 PCZT is JSON-representable");
    value["ironwood"] = ironwood_bundle_json((5_000, false));
    let v2: pczt::v2::Pczt = serde_json::from_value(value).expect("edited v2 PCZT deserializes");
    let bytes = v2.serialize();

    match pczt_verify(&bytes, &approved_tx(&recipient), &keys) {
        Err(_) => {}
        Ok(verdict) => panic!(
            "v5 PCZT carrying Ironwood value must be refused, got accounted={}",
            verdict.all_outputs_accounted
        ),
    }
}

#[test]
fn unknown_consensus_branch_id_is_refused() {
    // Branch IDs are opaque: an unknown ID — even one numerically above the
    // NU6.3 ID — must refuse at verify AND at sign, never "best effort" parse.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);
    let empty_signing_keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    };

    for bogus_branch in [0xDEAD_BEEFu32, 0x37A5_165C] {
        let pczt = build_v6_pczt(&recipient_hash, &owned, |value| {
            value["global"]["consensus_branch_id"] = json!(bogus_branch);
        });
        let bytes = wire(pczt);

        assert!(
            pczt_verify(&bytes, &approved_tx(&recipient), &keys).is_err(),
            "verify must refuse unknown branch {bogus_branch:#010x}"
        );
        assert!(
            sign_pczt(&bytes, &empty_signing_keys).is_err(),
            "sign must refuse unknown branch {bogus_branch:#010x}"
        );
    }
}

#[test]
fn malformed_ironwood_action_fails_closed() {
    // An Ironwood action whose crypto components are garbage (unparseable rk,
    // unresolvable value commitment) must refuse before approval controls
    // appear — never render as "0 actions" or be skipped.
    let (keys, owned) = wallet_keys();
    let recipient_hash = FOREIGN_HASH;
    let recipient = t_address(recipient_hash);

    let bogus_action = json!({
        "cv_net": null,
        "spend": {
            "nullifier": vec![0u8; 32],
            "rk": vec![0xAAu8; 32],
            "spend_auth_sig": null,
            "recipient": null,
            "value": 7_000u64,
            "rho": null,
            "rseed": null,
            "fvk": null,
            "witness": null,
            "alpha": null,
            "zip32_derivation": null,
            "dummy_sk": null,
            "proprietary": {},
        },
        "output": {
            "cmx": null,
            "ephemeral_key": vec![0u8; 32],
            "enc_ciphertext": {"Encrypted": vec![0u8; 580]},
            "out_ciphertext": vec![0u8; 80],
            "recipient": null,
            "value": 7_000u64,
            "rseed": null,
            "ock": null,
            "zip32_derivation": null,
            "user_address": null,
            "proprietary": {},
        },
        "rcv": null,
    });

    let pczt_json_edit = move |value: &mut Value| {
        let mut bundle = ironwood_bundle_json((0, false));
        bundle["actions"] = json!([bogus_action]);
        value["ironwood"] = bundle;
    };

    let mut value = empty_v6_pczt_json();
    value["transparent"] = json!({
        "inputs": [transparent_input_json(INPUT_VALUE, &owned, SIGHASH_ALL)],
        "outputs": [
            transparent_output_json(APPROVED_AMOUNT, &recipient_hash, None),
            transparent_output_json(CHANGE_VALUE, &owned, None),
        ],
    });
    pczt_json_edit(&mut value);

    // The malformed action must be refused at one of the fail-closed layers:
    // v2 decode, logical parse, field resolution, or the verifier's
    // conservation/ownership pass. It must never verify as fully accounted.
    let v2: Result<pczt::v2::Pczt, _> = serde_json::from_value(value);
    let Ok(v2) = v2 else {
        return; // refused at decode — fail-closed upstream of display
    };
    let bytes = v2.serialize();
    match pczt_verify(&bytes, &approved_tx(&recipient), &keys) {
        Err(_) => {}
        Ok(verdict) => {
            assert!(
                !verdict.all_outputs_accounted,
                "garbage Ironwood action must not verify as accounted"
            );
        }
    }
}
