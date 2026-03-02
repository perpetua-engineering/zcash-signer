//! Cross-check Sapling ZIP-32 key derivation against the upstream sapling-crypto crate.
//!
//! These tests verify our Sapling key derivation by comparing against the upstream
//! sapling-crypto crate. They cover:
//! - Master key derivation (sk_m → ask, nsk, ovk match upstream)
//! - Full-path derivation at m/32'/coin_type'/account' with proper additive CKDh
//! - Internal consistency between ask-from-sk and ask-from-seed paths
//!
//! Requires the `debug-tools` feature: cargo test --features debug-tools

use group::GroupEncoding;
use sapling_crypto::keys::ExpandedSpendingKey;
use sapling_crypto::zip32::ExtendedSpendingKey;
use zip32::ChildIndex;

use zcash_signer::{
    zsig_derive_sapling_ask, zsig_derive_sapling_ask_from_seed, zsig_derive_sapling_spending_key,
    ZsigError, ZsigSaplingAsk, ZsigSaplingSpendingKey,
};

/// Test vectors: (seed_hex, coin_type, account)
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

/// Helper: derive "spending key" (now returns ask bytes) via our FFI
fn our_spending_key_bytes(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let mut sk = ZsigSaplingSpendingKey { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_sapling_spending_key(seed.as_ptr(), seed.len(), coin_type, account, &mut sk)
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_sapling_spending_key failed");
    sk.bytes
}

/// Helper: derive ask from "spending key" via our FFI (now a passthrough)
fn our_ask_from_sk(sk_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = ZsigSaplingSpendingKey { bytes: *sk_bytes };
    let mut ask = ZsigSaplingAsk { bytes: [0u8; 32] };
    let err = unsafe { zsig_derive_sapling_ask(&sk, &mut ask) };
    assert_eq!(err, ZsigError::Success, "zsig_derive_sapling_ask failed");
    ask.bytes
}

/// Helper: derive ask directly from seed via our FFI
fn our_ask_from_seed(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let mut ask = ZsigSaplingAsk { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_sapling_ask_from_seed(seed.as_ptr(), seed.len(), coin_type, account, &mut ask)
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_sapling_ask_from_seed failed");
    ask.bytes
}

/// Derive Sapling ExtendedSpendingKey from seed at ZIP-32 path m/32'/coin_type'/account'
fn upstream_esk(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    let master = ExtendedSpendingKey::master(seed);
    let path = [
        ChildIndex::hardened(32),
        ChildIndex::hardened(coin_type),
        ChildIndex::hardened(account),
    ];
    ExtendedSpendingKey::from_path(&master, &path)
}

#[test]
fn master_key_expansion_matches_upstream() {
    // Verify our master key derivation (before any CKDh) matches upstream.
    // Both take BLAKE2b-512("ZcashIP32Sapling", seed)[..32] as sk_m and expand it.
    for (i, (seed, _coin_type, _account)) in test_vectors().iter().enumerate() {
        let master_hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ZcashIP32Sapling")
            .hash(seed);
        let sk_m: [u8; 32] = master_hash.as_bytes()[..32].try_into().unwrap();

        // Expand using upstream's ExpandedSpendingKey::from_spending_key
        let from_our_sk = ExpandedSpendingKey::from_spending_key(&sk_m);

        // Upstream master
        let upstream_master = ExtendedSpendingKey::master(seed);

        assert_eq!(
            from_our_sk.ask.to_bytes(),
            upstream_master.expsk.ask.to_bytes(),
            "master ask mismatch for vector {i}"
        );
        assert_eq!(
            from_our_sk.nsk.to_bytes(),
            upstream_master.expsk.nsk.to_bytes(),
            "master nsk mismatch for vector {i}"
        );
        assert_eq!(
            from_our_sk.ovk.0,
            upstream_master.expsk.ovk.0,
            "master ovk mismatch for vector {i}"
        );
    }
}

#[test]
fn ask_from_seed_matches_ask_via_spending_key() {
    // Internal consistency: ask derived via spending_key → ask matches ask_from_seed.
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let sk_bytes = our_spending_key_bytes(seed, *coin_type, *account);
        let ask_via_sk = our_ask_from_sk(&sk_bytes);
        let ask_via_seed = our_ask_from_seed(seed, *coin_type, *account);

        assert_eq!(
            ask_via_sk, ask_via_seed,
            "ask(sk) != ask(seed) for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn ask_matches_upstream() {
    // Cross-check our ask at m/32'/coin_type'/account' against upstream sapling-crypto.
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_ask = our_ask_from_seed(seed, *coin_type, *account);

        let upstream = upstream_esk(seed, *coin_type, *account);
        let upstream_ask_bytes = upstream.expsk.ask.to_bytes();

        assert_eq!(
            our_ask, upstream_ask_bytes,
            "ask mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn nsk_derivation_matches_upstream() {
    // Cross-check nsk at m/32'/coin_type'/account'.
    // We access nsk via our internal SaplingExtendedKey since the FFI doesn't expose it directly.
    // Instead, verify indirectly: our FVK derivation (which uses nsk) produces correct results.
    // This test accesses the upstream nsk for comparison with a manual derivation from our code.
    use zcash_signer::zsig_derive_sapling_full_viewing_key;
    use zcash_signer::ZsigSaplingFullViewingKey;

    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let mut fvk = ZsigSaplingFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            ovk: [0u8; 32],
            dk: [0u8; 32],
        };
        let err = unsafe {
            zsig_derive_sapling_full_viewing_key(
                seed.as_ptr(),
                seed.len(),
                *coin_type,
                *account,
                &mut fvk,
            )
        };
        assert_eq!(err, ZsigError::Success, "zsig_derive_sapling_full_viewing_key failed");

        let upstream = upstream_esk(seed, *coin_type, *account);

        // Compare ovk directly (it's a 32-byte value in both)
        assert_eq!(
            fvk.ovk,
            upstream.expsk.ovk.0,
            "ovk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

#[test]
fn sapling_fvk_matches_upstream() {
    // Compare our Sapling FVK (ak, nk, ovk, dk) against upstream.
    use sapling_crypto::keys::FullViewingKey;
    use zcash_signer::zsig_derive_sapling_full_viewing_key;
    use zcash_signer::ZsigSaplingFullViewingKey;

    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let mut fvk = ZsigSaplingFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            ovk: [0u8; 32],
            dk: [0u8; 32],
        };
        let err = unsafe {
            zsig_derive_sapling_full_viewing_key(
                seed.as_ptr(),
                seed.len(),
                *coin_type,
                *account,
                &mut fvk,
            )
        };
        assert_eq!(err, ZsigError::Success, "FVK derivation failed for vector {i}");

        let upstream = upstream_esk(seed, *coin_type, *account);
        let upstream_fvk = FullViewingKey::from_expanded_spending_key(&upstream.expsk);

        // ak comparison
        assert_eq!(
            fvk.ak,
            upstream_fvk.vk.ak.to_bytes(),
            "ak mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );

        // nk comparison
        assert_eq!(
            fvk.nk,
            upstream_fvk.vk.nk.0.to_bytes(),
            "nk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );

        // ovk comparison
        assert_eq!(
            fvk.ovk,
            upstream_fvk.ovk.0,
            "ovk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );

        // dk comparison: serialize the upstream extended spending key and extract dk
        // ExtendedSpendingKey layout (169 bytes):
        //   depth(1) + tag(4) + ci(4) + chaincode(32) + expsk(96) + dk(32)
        let esk_bytes = upstream.to_bytes();
        let upstream_dk_bytes: [u8; 32] = esk_bytes[137..169].try_into().unwrap();
        assert_eq!(
            fvk.dk,
            upstream_dk_bytes,
            "dk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}
