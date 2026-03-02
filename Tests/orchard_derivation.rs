//! Cross-check Orchard ZIP-32 key derivation against the upstream orchard crate.
//!
//! These tests derive spending key, ask, ak, nk, and rivk through our code
//! (via FFI functions) and through the upstream orchard crate, then assert
//! byte-identical output across multiple seeds, account indices, and coin types.
//!
//! Requires the `debug-tools` feature: cargo test --features debug-tools

use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use zip32::AccountId;

use zcash_signer::{
    zsig_derive_orchard_ask, zsig_derive_orchard_ask_from_seed,
    zsig_derive_orchard_full_viewing_key, zsig_derive_orchard_spending_key, ZsigError,
    ZsigOrchardAsk, ZsigOrchardFullViewingKey, ZsigOrchardSpendingKey,
};

/// Test vectors: (seed_hex, coin_type, account)
/// Covers the "abandon" mnemonic seed, a random 64-byte seed, a random 32-byte seed,
/// plus varied account indices and coin types.
fn test_vectors() -> Vec<(Vec<u8>, u32, u32)> {
    vec![
        // "abandon ... about" mnemonic → 64-byte BIP-39 seed (empty passphrase)
        (
            hex::decode(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            )
            .unwrap(),
            133, // Zcash mainnet
            0,
        ),
        // Same seed, account 1
        (
            hex::decode(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            )
            .unwrap(),
            133,
            1,
        ),
        // Same seed, account 5
        (
            hex::decode(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            )
            .unwrap(),
            133,
            5,
        ),
        // Same seed, testnet coin type
        (
            hex::decode(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            )
            .unwrap(),
            1, // testnet
            0,
        ),
        // Random 64-byte seed, account 0
        (
            hex::decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            )
            .unwrap(),
            133,
            0,
        ),
        // Random 64-byte seed, account 3
        (
            hex::decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            )
            .unwrap(),
            133,
            3,
        ),
        // Minimal 32-byte seed
        (
            hex::decode(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
            133,
            0,
        ),
    ]
}

/// Helper: derive spending key via our FFI
fn our_spending_key(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let mut sk = ZsigOrchardSpendingKey { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_orchard_spending_key(seed.as_ptr(), seed.len(), coin_type, account, &mut sk)
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_spending_key failed");
    sk.bytes
}

/// Helper: derive ask from spending key via our FFI
fn our_ask_from_sk(sk_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = ZsigOrchardSpendingKey { bytes: *sk_bytes };
    let mut ask = ZsigOrchardAsk { bytes: [0u8; 32] };
    let err = unsafe { zsig_derive_orchard_ask(&sk, &mut ask) };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_ask failed");
    ask.bytes
}

/// Helper: derive ask directly from seed via our FFI
fn our_ask_from_seed(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let mut ask = ZsigOrchardAsk { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_orchard_ask_from_seed(seed.as_ptr(), seed.len(), coin_type, account, &mut ask)
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_ask_from_seed failed");
    ask.bytes
}

/// Helper: derive FVK (ak, nk, rivk) via our FFI
fn our_fvk(seed: &[u8], coin_type: u32, account: u32) -> ZsigOrchardFullViewingKey {
    let mut fvk = ZsigOrchardFullViewingKey {
        ak: [0u8; 32],
        nk: [0u8; 32],
        rivk: [0u8; 32],
    };
    let err = unsafe {
        zsig_derive_orchard_full_viewing_key(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut fvk,
        )
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_full_viewing_key failed");
    fvk
}

/// Helper: derive upstream orchard SpendingKey
fn upstream_spending_key(seed: &[u8], coin_type: u32, account: u32) -> SpendingKey {
    let account_id = AccountId::try_from(account).expect("valid account index");
    SpendingKey::from_zip32_seed(seed, coin_type, account_id)
        .expect("upstream SpendingKey derivation failed")
}

#[test]
fn spending_key_matches_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let ours = our_spending_key(seed, *coin_type, *account);
        let upstream = upstream_spending_key(seed, *coin_type, *account);

        assert_eq!(
            ours,
            *upstream.to_bytes(),
            "spending key mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn ask_matches_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_sk = our_spending_key(seed, *coin_type, *account);
        let our_ask = our_ask_from_sk(&our_sk);

        let upstream_sk = upstream_spending_key(seed, *coin_type, *account);
        let upstream_ask = SpendAuthorizingKey::from(&upstream_sk);

        assert_eq!(
            our_ask,
            upstream_ask.to_bytes(),
            "ask mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn ask_from_seed_matches_ask_from_sk() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_sk = our_spending_key(seed, *coin_type, *account);
        let ask_via_sk = our_ask_from_sk(&our_sk);
        let ask_via_seed = our_ask_from_seed(seed, *coin_type, *account);

        assert_eq!(
            ask_via_sk, ask_via_seed,
            "ask(sk) != ask(seed) for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn fvk_ak_nk_rivk_match_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our = our_fvk(seed, *coin_type, *account);

        let upstream_sk = upstream_spending_key(seed, *coin_type, *account);
        let upstream_fvk: FullViewingKey = (&upstream_sk).into();
        let upstream_bytes = upstream_fvk.to_bytes();

        // Upstream FVK layout: ak (32) || nk (32) || rivk (32) = 96 bytes
        let upstream_ak = &upstream_bytes[..32];
        let upstream_nk = &upstream_bytes[32..64];
        let upstream_rivk = &upstream_bytes[64..96];

        assert_eq!(
            our.ak, upstream_ak,
            "ak mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our.nk, upstream_nk,
            "nk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our.rivk, upstream_rivk,
            "rivk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}
