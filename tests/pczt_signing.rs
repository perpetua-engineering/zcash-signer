//! PCZT signer regression tests.
//!
//! These keep the watch-side PCZT entrypoints exercised with deterministic
//! bytes. Live sign -> prove -> txid coverage remains in the funded-wallet
//! roundtrip script because generating proofs requires SDK state and fixtures.

#![cfg(feature = "pczt-signer")]

use pczt::roles::creator::Creator;
use zcash_protocol::consensus::BranchId;
use zcash_signer::pczt_signer::{pczt_info, sign_pczt, PcztSignError, PcztSigningKeys};

fn empty_pczt_bytes() -> Vec<u8> {
    Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
        .build()
        .serialize()
}

fn no_signing_keys<'a>() -> PcztSigningKeys<'a> {
    PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    }
}

#[test]
fn pczt_info_parses_real_serialized_pczt() {
    let pczt = empty_pczt_bytes();
    let info = pczt_info(&pczt).expect("empty creator PCZT should parse");

    assert_eq!(info.orchard_actions, 0);
    assert_eq!(info.sapling_spends, 0);
    assert_eq!(info.transparent_inputs, 0);
    assert_eq!(info.transparent_outputs, 0);
}

#[test]
fn sign_pczt_handles_parseable_pczt_without_spends() {
    let pczt = empty_pczt_bytes();
    let signed = sign_pczt(&pczt, &no_signing_keys())
        .expect("empty creator PCZT should be a no-op signer pass");
    let info = pczt_info(&signed).expect("signed PCZT should remain parseable");

    assert_eq!(info.orchard_actions, 0);
    assert_eq!(info.sapling_spends, 0);
    assert_eq!(info.transparent_inputs, 0);
    assert_eq!(info.transparent_outputs, 0);
}

#[test]
fn sign_pczt_rejects_malformed_sapling_ask_without_panicking() {
    // CR-1337 gap 4: a zero (or non-canonical) Sapling ask used to panic
    // (abort) deep in sapling-crypto's eager `redjubjub::SigningKey::try_from`.
    // It must now return `InvalidSaplingKey` cleanly. `sapling_esk_from_ask`
    // runs whenever a Sapling key is supplied, independent of spend count, so an
    // empty creator PCZT exercises the validation.
    let pczt = empty_pczt_bytes();

    let zero_ask = [0u8; 32];
    let keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: Some(&zero_ask),
        transparent_sk: None,
    };
    assert!(matches!(
        sign_pczt(&pczt, &keys),
        Err(PcztSignError::InvalidSaplingKey)
    ));

    // 0xFF..FF is a non-canonical Jubjub scalar encoding (> modulus).
    let noncanonical_ask = [0xFFu8; 32];
    let keys = PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: Some(&noncanonical_ask),
        transparent_sk: None,
    };
    assert!(matches!(
        sign_pczt(&pczt, &keys),
        Err(PcztSignError::InvalidSaplingKey)
    ));
}

#[test]
fn pczt_entrypoints_reject_malformed_inputs_without_panicking() {
    let cases: &[&[u8]] = &[
        b"",
        b"PCZT",
        b"PCZT\x01\x00\x00\x00",
        b"NOTP\x01\x00\x00\x00",
        b"PCZT\xff\xff\xff\xff",
    ];

    for bytes in cases {
        assert!(matches!(pczt_info(bytes), Err(PcztSignError::ParseFailed)));
        assert!(matches!(
            sign_pczt(bytes, &no_signing_keys()),
            Err(PcztSignError::ParseFailed)
        ));
    }
}
