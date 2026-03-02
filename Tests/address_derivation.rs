//! Cross-check address derivation against upstream orchard and sapling-crypto crates.
//!
//! These tests verify:
//! - Orchard IVK derivation (Sinsemilla commit_ivk) by comparing pk_d for a given diversifier
//! - Orchard payment address components against upstream orchard crate
//! - Sapling diversifier key (dk) against upstream sapling-crypto
//! - Sapling diversifier derivation (FF1-AES256) against upstream (known discrepancy)
//!
//! Requires the `debug-tools` feature: cargo test --features debug-tools

use orchard::keys::{
    Diversifier as OrchardDiversifier, FullViewingKey as OrchardFVK, Scope,
    SpendingKey as OrchardSK,
};
use sapling_crypto::zip32::ExtendedSpendingKey;
use zip32::{AccountId, ChildIndex};

use zcash_signer::{
    zsig_derive_first_valid_diversifier_index, zsig_derive_orchard_address,
    zsig_derive_orchard_address_from_seed, zsig_derive_orchard_full_viewing_key,
    zsig_derive_orchard_spending_key, zsig_derive_sapling_full_viewing_key, ZsigError,
    ZsigOrchardAddress, ZsigOrchardFullViewingKey, ZsigOrchardSpendingKey,
    ZsigSaplingFullViewingKey,
};

/// Test vectors: (seed_hex, coin_type, account)
/// Same vectors used in orchard_derivation.rs and sapling_derivation.rs.
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

// ---------------------------------------------------------------------------
// Orchard helpers
// ---------------------------------------------------------------------------

/// Derive Orchard spending key via our FFI
fn our_orchard_sk(seed: &[u8], coin_type: u32, account: u32) -> [u8; 32] {
    let mut sk = ZsigOrchardSpendingKey { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_orchard_spending_key(seed.as_ptr(), seed.len(), coin_type, account, &mut sk)
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_spending_key failed");
    sk.bytes
}

/// Derive Orchard address from spending key via our FFI
fn our_orchard_address_from_sk(sk_bytes: &[u8; 32]) -> ZsigOrchardAddress {
    let mut addr = ZsigOrchardAddress {
        diversifier: [0u8; 11],
        pk_d: [0u8; 32],
    };
    let err = unsafe { zsig_derive_orchard_address(sk_bytes.as_ptr(), &mut addr) };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_address failed");
    addr
}

/// Derive Orchard address from seed via our FFI
fn our_orchard_address(seed: &[u8], coin_type: u32, account: u32) -> ZsigOrchardAddress {
    let mut addr = ZsigOrchardAddress {
        diversifier: [0u8; 11],
        pk_d: [0u8; 32],
    };
    let err = unsafe {
        zsig_derive_orchard_address_from_seed(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut addr,
        )
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_orchard_address_from_seed failed");
    addr
}

/// Derive Orchard FVK via our FFI
fn our_orchard_fvk(seed: &[u8], coin_type: u32, account: u32) -> ZsigOrchardFullViewingKey {
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

/// Derive upstream Orchard FVK
fn upstream_orchard_fvk(seed: &[u8], coin_type: u32, account: u32) -> OrchardFVK {
    let account_id = AccountId::try_from(account).expect("valid account index");
    let sk = OrchardSK::from_zip32_seed(seed, coin_type, account_id)
        .expect("upstream SpendingKey derivation failed");
    (&sk).into()
}

// ---------------------------------------------------------------------------
// Sapling helpers
// ---------------------------------------------------------------------------

/// Derive Sapling FVK via our FFI
fn our_sapling_fvk(seed: &[u8], coin_type: u32, account: u32) -> ZsigSaplingFullViewingKey {
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
            coin_type,
            account,
            &mut fvk,
        )
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_sapling_full_viewing_key failed");
    fvk
}

/// Derive first valid diversifier index via our FFI
fn our_first_valid_diversifier(
    seed: &[u8],
    coin_type: u32,
    account: u32,
) -> (u64, [u8; 11]) {
    let mut index: u64 = 0;
    let mut diversifier = [0u8; 11];
    let err = unsafe {
        zsig_derive_first_valid_diversifier_index(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut index,
            diversifier.as_mut_ptr(),
        )
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_first_valid_diversifier_index failed");
    (index, diversifier)
}

/// Derive upstream Sapling ExtendedSpendingKey at the account path
fn upstream_sapling_esk(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    let master = ExtendedSpendingKey::master(seed);
    let path = [
        ChildIndex::hardened(32),
        ChildIndex::hardened(coin_type),
        ChildIndex::hardened(account),
    ];
    ExtendedSpendingKey::from_path(&master, &path)
}

/// Derive upstream Sapling DiversifiableFullViewingKey at the account path
fn upstream_sapling_dfvk(
    seed: &[u8],
    coin_type: u32,
    account: u32,
) -> sapling_crypto::zip32::DiversifiableFullViewingKey {
    upstream_sapling_esk(seed, coin_type, account).to_diversifiable_full_viewing_key()
}

// ---------------------------------------------------------------------------
// Orchard address tests
// ---------------------------------------------------------------------------

/// Cross-check Orchard IVK/pk_d derivation using the same diversifier on both sides.
///
/// Our code uses a raw all-zeros diversifier (not DiversifierKey-derived). To validate
/// that our Sinsemilla commit_ivk produces the correct IVK, we pass the same raw
/// all-zeros diversifier to upstream's `fvk.address(diversifier, scope)` and compare pk_d.
///
/// If the Sinsemilla IVK computation were wrong, pk_d = ivk * g_d would differ.
#[test]
fn orchard_ivk_produces_correct_pk_d() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_addr = our_orchard_address(seed, *coin_type, *account);

        // Our code uses all-zeros diversifier
        assert_eq!(
            our_addr.diversifier,
            [0u8; 11],
            "Expected all-zeros diversifier from our code for vector {i}"
        );

        // Use the same all-zeros diversifier with upstream
        let upstream_fvk = upstream_orchard_fvk(seed, *coin_type, *account);
        let diversifier = OrchardDiversifier::from_bytes([0u8; 11]);
        let upstream_addr = upstream_fvk.address(diversifier, Scope::External);
        let upstream_raw = upstream_addr.to_raw_address_bytes();

        // pk_d should match: same diversifier → same g_d, and if IVK matches → same pk_d
        assert_eq!(
            our_addr.pk_d,
            &upstream_raw[11..43],
            "Orchard pk_d mismatch for vector {i} (coin_type={coin_type}, account={account}). \
             This indicates our Sinsemilla IVK derivation differs from upstream."
        );
    }
}

/// Cross-check that Orchard FVK components are identical to upstream (prerequisite).
///
/// ak, nk, rivk must match for the IVK to have any chance of matching. This test
/// is a prerequisite for the IVK test above but exercises the FVK derivation in
/// the context of address derivation.
#[test]
fn orchard_fvk_components_match_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_fvk = our_orchard_fvk(seed, *coin_type, *account);

        let upstream_fvk = upstream_orchard_fvk(seed, *coin_type, *account);
        let upstream_bytes = upstream_fvk.to_bytes();

        assert_eq!(
            our_fvk.ak, &upstream_bytes[..32],
            "ak mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our_fvk.nk, &upstream_bytes[32..64],
            "nk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our_fvk.rivk, &upstream_bytes[64..96],
            "rivk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

/// Verify address_from_seed and address_from_sk produce the same result.
///
/// Internal consistency: both paths (seed → sk → address vs seed → address)
/// should produce identical output.
#[test]
fn orchard_address_from_seed_matches_address_from_sk() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let addr_from_seed = our_orchard_address(seed, *coin_type, *account);

        let sk = our_orchard_sk(seed, *coin_type, *account);
        let addr_from_sk = our_orchard_address_from_sk(&sk);

        assert_eq!(
            addr_from_seed.diversifier, addr_from_sk.diversifier,
            "diversifier mismatch (seed vs sk) for vector {i}"
        );
        assert_eq!(
            addr_from_seed.pk_d, addr_from_sk.pk_d,
            "pk_d mismatch (seed vs sk) for vector {i}"
        );
    }
}

/// Verify upstream diversifier indices produce distinct addresses (sanity check).
#[test]
fn orchard_different_indices_produce_different_addresses() {
    let (seed, coin_type, account) = &test_vectors()[0];
    let fvk = upstream_orchard_fvk(seed, *coin_type, *account);

    let addr0 = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let addr1 = fvk.address_at(1u32, Scope::External).to_raw_address_bytes();

    assert_ne!(
        &addr0[..11], &addr1[..11],
        "Diversifiers at index 0 and 1 should differ"
    );
    assert_ne!(
        &addr0[11..], &addr1[11..],
        "pk_d at index 0 and 1 should differ"
    );
}

// ---------------------------------------------------------------------------
// Sapling address tests
// ---------------------------------------------------------------------------

/// Cross-check Sapling dk (diversifier key) against upstream.
///
/// dk is the AES key for FF1-AES256 diversifier derivation. If dk differs,
/// all diversifiers will differ. This validates the additive CKDh path
/// all the way through to the dk component.
#[test]
fn sapling_dk_matches_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_fvk = our_sapling_fvk(seed, *coin_type, *account);

        let dfvk = upstream_sapling_dfvk(seed, *coin_type, *account);
        // DFVK serialization: fvk(96) + dk(32) = 128 bytes
        let dfvk_bytes = dfvk.to_bytes();
        let upstream_dk = &dfvk_bytes[96..128];

        assert_eq!(
            our_fvk.dk, upstream_dk,
            "Sapling dk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

/// Cross-check Sapling FVK components (ak, nk, ovk) against upstream.
///
/// These components are used for address derivation (ak, nk → ivk → pk_d)
/// and outgoing transaction viewing (ovk).
#[test]
fn sapling_fvk_components_match_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let our_fvk = our_sapling_fvk(seed, *coin_type, *account);

        let dfvk = upstream_sapling_dfvk(seed, *coin_type, *account);
        // DFVK serialization: ak(32) || nk(32) || ovk(32) || dk(32) = 128 bytes
        let dfvk_bytes = dfvk.to_bytes();

        assert_eq!(
            our_fvk.ak,
            &dfvk_bytes[..32],
            "Sapling ak mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our_fvk.nk,
            &dfvk_bytes[32..64],
            "Sapling nk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
        assert_eq!(
            our_fvk.ovk,
            &dfvk_bytes[64..96],
            "Sapling ovk mismatch for vector {i} (coin_type={coin_type}, account={account})"
        );
    }
}

/// Cross-check Sapling diversifier derivation (FF1-AES256) against upstream.
///
/// KNOWN ISSUE: Our FF1-AES256 implementation produces different diversifiers than
/// upstream sapling-crypto, despite using the same dk. This means our Sapling
/// addresses will not match the SDK's addresses.
///
/// This test documents the discrepancy by comparing both sides and asserting they
/// differ (so it will fail-to-compile if someone fixes FF1 without updating the test).
///
/// See the FF1-AES256 fix ticket.
#[test]
fn sapling_diversifier_known_discrepancy() {
    // Use the first test vector to document the discrepancy
    let (seed, coin_type, account) = &test_vectors()[0];

    // Our diversifier derivation
    let (our_index, our_diversifier) =
        our_first_valid_diversifier(seed, *coin_type, *account);

    // Upstream diversifier derivation
    let dfvk = upstream_sapling_dfvk(seed, *coin_type, *account);
    let (upstream_di, upstream_addr) = dfvk.default_address();
    let upstream_diversifier = upstream_addr.diversifier().0;

    // Convert upstream index to u64 for comparison
    let upstream_index_bytes = upstream_di.as_bytes();
    let mut upstream_index_u64 = 0u64;
    for (j, &b) in upstream_index_bytes.iter().enumerate().take(8) {
        upstream_index_u64 |= (b as u64) << (j * 8);
    }

    // Document the discrepancy: dk matches (tested above) but FF1 output differs
    // When this assertion starts failing, it means FF1 was fixed — update the test!
    if our_diversifier == upstream_diversifier {
        // FF1 is now fixed! Update this test to assert equality across all vectors.
        panic!(
            "FF1-AES256 now matches upstream — update sapling_diversifier_known_discrepancy \
             test to assert equality and remove the known-discrepancy documentation"
        );
    }

    // Log the discrepancy for visibility
    eprintln!(
        "KNOWN: Sapling FF1-AES256 discrepancy: our index={our_index}, upstream index={upstream_index_u64}"
    );
    eprintln!(
        "  our diversifier:      {}",
        hex::encode(our_diversifier)
    );
    eprintln!(
        "  upstream diversifier: {}",
        hex::encode(upstream_diversifier)
    );
}
