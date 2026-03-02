//! Cross-check UFVK (Unified Full Viewing Key) encoding against upstream crates.
//!
//! These tests verify that our ZIP-316 UFVK encoding (F4Jumble + Bech32m) produces
//! identical output to independently constructing the encoding using:
//! - `f4jumble` crate for the F4Jumble transform
//! - `bech32` crate for Bech32m encoding
//!
//! We cross-check:
//! - Orchard-only UFVK encoding (typecode 0x03)
//! - Combined UFVK encoding (transparent + sapling + orchard)
//! - HRP correctness for mainnet ("uview") and testnet ("uviewtest")
//! - Round-trip: decode our output → verify TLV structure contains correct FVK bytes
//!
//! Requires the `debug-tools` feature: cargo test --features debug-tools

use bech32::{Bech32m, Hrp};
use orchard::keys::{FullViewingKey as OrchardFVK, SpendingKey as OrchardSK};
use zip32::AccountId;

use zcash_signer::{
    zsig_derive_combined_full_viewing_key, zsig_derive_combined_ufvk_string,
    zsig_derive_orchard_full_viewing_key, zsig_derive_ufvk_string,
    zsig_encode_combined_full_viewing_key, zsig_encode_unified_full_viewing_key,
    ZsigCombinedFullViewingKey, ZsigError, ZsigOrchardFullViewingKey,
    ZsigSaplingFullViewingKey, ZsigTransparentFullViewingKey,
};

/// Test vectors: (seed_hex, coin_type, account)
/// Same vectors used across all CR-745 cross-check tests.
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
// Helpers
// ---------------------------------------------------------------------------

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

/// Encode Orchard-only UFVK via our FFI, returns the string
fn our_orchard_ufvk_string(fvk: &ZsigOrchardFullViewingKey, mainnet: bool) -> String {
    let mut buf = [0u8; 512];
    let len = unsafe {
        zsig_encode_unified_full_viewing_key(fvk as *const _, mainnet, buf.as_mut_ptr(), 512)
    };
    assert!(len > 0, "zsig_encode_unified_full_viewing_key returned 0");
    String::from_utf8(buf[..len].to_vec()).expect("valid UTF-8")
}

/// Derive UFVK string from seed via our FFI convenience function
fn our_ufvk_from_seed(seed: &[u8], coin_type: u32, account: u32, mainnet: bool) -> String {
    let mut buf = [0u8; 512];
    let len = unsafe {
        zsig_derive_ufvk_string(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            mainnet,
            buf.as_mut_ptr(),
            512,
        )
    };
    assert!(len > 0, "zsig_derive_ufvk_string returned negative: {len}");
    String::from_utf8(buf[..len as usize].to_vec()).expect("valid UTF-8")
}

/// Derive combined FVK via our FFI
fn our_combined_fvk(
    seed: &[u8],
    coin_type: u32,
    account: u32,
) -> ZsigCombinedFullViewingKey {
    let mut fvk = ZsigCombinedFullViewingKey {
        transparent: ZsigTransparentFullViewingKey {
            chain_code: [0u8; 32],
            pubkey: [0u8; 33],
        },
        sapling: ZsigSaplingFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            ovk: [0u8; 32],
            dk: [0u8; 32],
        },
        orchard: ZsigOrchardFullViewingKey {
            ak: [0u8; 32],
            nk: [0u8; 32],
            rivk: [0u8; 32],
        },
    };
    let err = unsafe {
        zsig_derive_combined_full_viewing_key(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut fvk,
        )
    };
    assert_eq!(err, ZsigError::Success, "zsig_derive_combined_full_viewing_key failed");
    fvk
}

/// Encode combined UFVK via our FFI
fn our_combined_ufvk_string(fvk: &ZsigCombinedFullViewingKey, mainnet: bool) -> String {
    let mut buf = [0u8; 1024];
    let len = unsafe {
        zsig_encode_combined_full_viewing_key(fvk as *const _, mainnet, buf.as_mut_ptr(), 1024)
    };
    assert!(len > 0, "zsig_encode_combined_full_viewing_key returned 0");
    String::from_utf8(buf[..len].to_vec()).expect("valid UTF-8")
}

/// Derive combined UFVK string from seed via our FFI convenience function
fn our_combined_ufvk_from_seed(
    seed: &[u8],
    coin_type: u32,
    account: u32,
    mainnet: bool,
) -> String {
    let mut buf = [0u8; 1024];
    let len = unsafe {
        zsig_derive_combined_ufvk_string(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            mainnet,
            buf.as_mut_ptr(),
            1024,
        )
    };
    assert!(len > 0, "zsig_derive_combined_ufvk_string returned negative: {len}");
    String::from_utf8(buf[..len as usize].to_vec()).expect("valid UTF-8")
}

/// Independently construct an Orchard-only UFVK string using upstream f4jumble + bech32 crates.
///
/// This replicates the ZIP-316 encoding from scratch without touching our code:
/// 1. Build TLV: [0x03][96][ak||nk||rivk]
/// 2. Append HRP padding (16 bytes, right-padded with zeros)
/// 3. F4Jumble the entire payload
/// 4. Bech32m encode with the HRP
fn reference_orchard_ufvk(ak: &[u8; 32], nk: &[u8; 32], rivk: &[u8; 32], mainnet: bool) -> String {
    let hrp_str = if mainnet { "uview" } else { "uviewtest" };

    // Build raw TLV + HRP padding (98 + 16 = 114 bytes)
    let mut raw = [0u8; 114];
    raw[0] = 0x03; // Orchard typecode
    raw[1] = 96;   // Length: 3 * 32
    raw[2..34].copy_from_slice(ak);
    raw[34..66].copy_from_slice(nk);
    raw[66..98].copy_from_slice(rivk);
    // HRP padding at bytes [98..114]
    let hrp_bytes = hrp_str.as_bytes();
    raw[98..98 + hrp_bytes.len()].copy_from_slice(hrp_bytes);
    // Remaining bytes are already zeros

    // F4Jumble using upstream crate
    let jumbled = f4jumble::f4jumble(&raw).expect("f4jumble failed");

    // Bech32m encode using upstream crate
    let hrp = Hrp::parse(hrp_str).expect("valid HRP");
    bech32::encode::<Bech32m>(hrp, &jumbled).expect("bech32m encode failed")
}

/// Independently construct a combined UFVK string using upstream f4jumble + bech32 crates.
///
/// TLV layout per ZIP-316 (receivers ordered by typecode ascending):
/// - Transparent P2PKH: [0x00][65][chain_code(32) || pubkey(33)]
/// - Sapling:           [0x02][128][ak(32) || nk(32) || ovk(32) || dk(32)]
/// - Orchard:           [0x03][96][ak(32) || nk(32) || rivk(32)]
/// + 16-byte HRP padding
fn reference_combined_ufvk(fvk: &ZsigCombinedFullViewingKey, mainnet: bool) -> String {
    let hrp_str = if mainnet { "uview" } else { "uviewtest" };

    // Total: 67 + 130 + 98 + 16 = 311 bytes
    let mut raw = [0u8; 311];

    // Transparent P2PKH FVK (typecode 0x00)
    raw[0] = 0x00;
    raw[1] = 65; // 32 + 33
    raw[2..34].copy_from_slice(&fvk.transparent.chain_code);
    raw[34..67].copy_from_slice(&fvk.transparent.pubkey);

    // Sapling FVK (typecode 0x02)
    raw[67] = 0x02;
    raw[68] = 128; // 4 * 32
    raw[69..101].copy_from_slice(&fvk.sapling.ak);
    raw[101..133].copy_from_slice(&fvk.sapling.nk);
    raw[133..165].copy_from_slice(&fvk.sapling.ovk);
    raw[165..197].copy_from_slice(&fvk.sapling.dk);

    // Orchard FVK (typecode 0x03)
    raw[197] = 0x03;
    raw[198] = 96; // 3 * 32
    raw[199..231].copy_from_slice(&fvk.orchard.ak);
    raw[231..263].copy_from_slice(&fvk.orchard.nk);
    raw[263..295].copy_from_slice(&fvk.orchard.rivk);

    // HRP padding at bytes [295..311]
    let hrp_bytes = hrp_str.as_bytes();
    raw[295..295 + hrp_bytes.len()].copy_from_slice(hrp_bytes);

    // F4Jumble using upstream crate
    let jumbled = f4jumble::f4jumble(&raw).expect("f4jumble failed");

    // Bech32m encode using upstream crate
    let hrp = Hrp::parse(hrp_str).expect("valid HRP");
    bech32::encode::<Bech32m>(hrp, &jumbled).expect("bech32m encode failed")
}

// ---------------------------------------------------------------------------
// Tests: Orchard-only UFVK encoding
// ---------------------------------------------------------------------------

/// Cross-check Orchard-only UFVK encoding against upstream f4jumble + bech32.
///
/// For each test vector:
/// 1. Derive Orchard FVK via our code
/// 2. Encode as UFVK via our code
/// 3. Independently construct the same UFVK using upstream f4jumble + bech32
/// 4. Assert byte-identical output
#[test]
fn orchard_ufvk_encoding_matches_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let fvk = our_orchard_fvk(seed, *coin_type, *account);
        let mainnet = *coin_type == 133;

        let our_ufvk = our_orchard_ufvk_string(&fvk, mainnet);
        let ref_ufvk = reference_orchard_ufvk(&fvk.ak, &fvk.nk, &fvk.rivk, mainnet);

        assert_eq!(
            our_ufvk, ref_ufvk,
            "Orchard-only UFVK encoding mismatch for vector {i} \
             (coin_type={coin_type}, account={account})"
        );
    }
}

/// Cross-check that zsig_derive_ufvk_string matches zsig_encode_unified_full_viewing_key.
///
/// Internal consistency: the convenience function (seed → string) should produce
/// the same result as derive-then-encode.
#[test]
fn ufvk_derive_string_matches_encode() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let mainnet = *coin_type == 133;

        let fvk = our_orchard_fvk(seed, *coin_type, *account);
        let from_encode = our_orchard_ufvk_string(&fvk, mainnet);
        let from_derive = our_ufvk_from_seed(seed, *coin_type, *account, mainnet);

        assert_eq!(
            from_encode, from_derive,
            "UFVK encode vs derive mismatch for vector {i}"
        );
    }
}

/// Verify Orchard UFVK uses correct HRP for mainnet vs testnet.
#[test]
fn orchard_ufvk_hrp_correctness() {
    let (seed, _, account) = &test_vectors()[0];

    // Mainnet: "uview" prefix
    let fvk = our_orchard_fvk(seed, 133, *account);
    let mainnet_ufvk = our_orchard_ufvk_string(&fvk, true);
    assert!(
        mainnet_ufvk.starts_with("uview1"),
        "Mainnet UFVK should start with 'uview1', got: {}",
        &mainnet_ufvk[..10]
    );

    // Testnet: "uviewtest" prefix
    let testnet_ufvk = our_orchard_ufvk_string(&fvk, false);
    assert!(
        testnet_ufvk.starts_with("uviewtest1"),
        "Testnet UFVK should start with 'uviewtest1', got: {}",
        &testnet_ufvk[..14]
    );
}

/// Round-trip: decode our Orchard UFVK output and verify the TLV contains correct FVK bytes.
///
/// This tests that F4Jumble and Bech32m are correctly applied by:
/// 1. Encoding via our code
/// 2. Bech32m-decoding via upstream bech32
/// 3. F4Jumble-inverse via upstream f4jumble
/// 4. Parsing TLV and comparing ak||nk||rivk
#[test]
fn orchard_ufvk_round_trip_decode() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let fvk = our_orchard_fvk(seed, *coin_type, *account);
        let mainnet = *coin_type == 133;
        let ufvk_str = our_orchard_ufvk_string(&fvk, mainnet);

        // Bech32m decode
        let (hrp, data) = bech32::decode(&ufvk_str).expect("bech32m decode failed");
        let expected_hrp = if mainnet { "uview" } else { "uviewtest" };
        assert_eq!(hrp.as_str(), expected_hrp, "HRP mismatch for vector {i}");

        // F4Jumble inverse
        let unjumbled =
            f4jumble::f4jumble_inv(&data).expect("f4jumble_inv failed");

        // Verify TLV structure
        assert_eq!(unjumbled.len(), 114, "Expected 114 bytes (98 TLV + 16 HRP pad)");
        assert_eq!(unjumbled[0], 0x03, "Expected Orchard typecode 0x03");
        assert_eq!(unjumbled[1], 96, "Expected length 96");
        assert_eq!(
            &unjumbled[2..34],
            &fvk.ak,
            "ak mismatch in decoded TLV for vector {i}"
        );
        assert_eq!(
            &unjumbled[34..66],
            &fvk.nk,
            "nk mismatch in decoded TLV for vector {i}"
        );
        assert_eq!(
            &unjumbled[66..98],
            &fvk.rivk,
            "rivk mismatch in decoded TLV for vector {i}"
        );

        // Verify HRP padding
        let hrp_pad = &unjumbled[98..114];
        let expected_pad = {
            let mut p = [0u8; 16];
            let hb = expected_hrp.as_bytes();
            p[..hb.len()].copy_from_slice(hb);
            p
        };
        assert_eq!(
            hrp_pad, &expected_pad,
            "HRP padding mismatch in decoded TLV for vector {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: Combined UFVK encoding (transparent + sapling + orchard)
// ---------------------------------------------------------------------------

/// Cross-check combined UFVK encoding against upstream f4jumble + bech32.
///
/// This verifies the full multi-receiver UFVK with transparent P2PKH,
/// Sapling, and Orchard FVK components.
#[test]
fn combined_ufvk_encoding_matches_upstream() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let fvk = our_combined_fvk(seed, *coin_type, *account);
        let mainnet = *coin_type == 133;

        let our_ufvk = our_combined_ufvk_string(&fvk, mainnet);
        let ref_ufvk = reference_combined_ufvk(&fvk, mainnet);

        assert_eq!(
            our_ufvk, ref_ufvk,
            "Combined UFVK encoding mismatch for vector {i} \
             (coin_type={coin_type}, account={account})"
        );
    }
}

/// Cross-check that zsig_derive_combined_ufvk_string matches
/// zsig_encode_combined_full_viewing_key.
///
/// Internal consistency: convenience function should match derive-then-encode.
#[test]
fn combined_ufvk_derive_string_matches_encode() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let mainnet = *coin_type == 133;

        let fvk = our_combined_fvk(seed, *coin_type, *account);
        let from_encode = our_combined_ufvk_string(&fvk, mainnet);
        let from_derive = our_combined_ufvk_from_seed(seed, *coin_type, *account, mainnet);

        assert_eq!(
            from_encode, from_derive,
            "Combined UFVK encode vs derive mismatch for vector {i}"
        );
    }
}

/// Round-trip: decode our combined UFVK and verify TLV structure with all receivers.
#[test]
fn combined_ufvk_round_trip_decode() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let fvk = our_combined_fvk(seed, *coin_type, *account);
        let mainnet = *coin_type == 133;
        let ufvk_str = our_combined_ufvk_string(&fvk, mainnet);

        // Bech32m decode
        let (hrp, data) = bech32::decode(&ufvk_str).expect("bech32m decode failed");
        let expected_hrp = if mainnet { "uview" } else { "uviewtest" };
        assert_eq!(hrp.as_str(), expected_hrp, "HRP mismatch for vector {i}");

        // F4Jumble inverse
        let unjumbled =
            f4jumble::f4jumble_inv(&data).expect("f4jumble_inv failed");

        // Expected: 295 TLV bytes + 16 HRP pad = 311
        assert_eq!(unjumbled.len(), 311, "Expected 311 bytes for combined UFVK");

        // Transparent P2PKH (typecode 0x00, length 65)
        assert_eq!(unjumbled[0], 0x00, "Expected transparent typecode 0x00");
        assert_eq!(unjumbled[1], 65, "Expected transparent length 65");
        assert_eq!(
            &unjumbled[2..34],
            &fvk.transparent.chain_code,
            "chain_code mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[34..67],
            &fvk.transparent.pubkey,
            "pubkey mismatch for vector {i}"
        );

        // Sapling (typecode 0x02, length 128)
        assert_eq!(unjumbled[67], 0x02, "Expected Sapling typecode 0x02");
        assert_eq!(unjumbled[68], 128, "Expected Sapling length 128");
        assert_eq!(
            &unjumbled[69..101],
            &fvk.sapling.ak,
            "Sapling ak mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[101..133],
            &fvk.sapling.nk,
            "Sapling nk mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[133..165],
            &fvk.sapling.ovk,
            "Sapling ovk mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[165..197],
            &fvk.sapling.dk,
            "Sapling dk mismatch for vector {i}"
        );

        // Orchard (typecode 0x03, length 96)
        assert_eq!(unjumbled[197], 0x03, "Expected Orchard typecode 0x03");
        assert_eq!(unjumbled[198], 96, "Expected Orchard length 96");
        assert_eq!(
            &unjumbled[199..231],
            &fvk.orchard.ak,
            "Orchard ak mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[231..263],
            &fvk.orchard.nk,
            "Orchard nk mismatch for vector {i}"
        );
        assert_eq!(
            &unjumbled[263..295],
            &fvk.orchard.rivk,
            "Orchard rivk mismatch for vector {i}"
        );

        // HRP padding
        let hrp_pad = &unjumbled[295..311];
        let expected_pad = {
            let mut p = [0u8; 16];
            let hb = expected_hrp.as_bytes();
            p[..hb.len()].copy_from_slice(hb);
            p
        };
        assert_eq!(
            hrp_pad, &expected_pad,
            "HRP padding mismatch for vector {i}"
        );
    }
}

/// Verify that Orchard FVK components in our UFVK match upstream orchard crate derivation.
///
/// This ties the encoding test back to the upstream key derivation: derive FVK via
/// upstream orchard crate, encode via our code AND reference code, verify both match.
#[test]
fn ufvk_fvk_bytes_match_upstream_orchard() {
    for (i, (seed, coin_type, account)) in test_vectors().iter().enumerate() {
        let account_id = AccountId::try_from(*account).expect("valid account index");
        let upstream_sk = OrchardSK::from_zip32_seed(seed, *coin_type, account_id)
            .expect("upstream SpendingKey derivation failed");
        let upstream_fvk: OrchardFVK = (&upstream_sk).into();
        let upstream_bytes = upstream_fvk.to_bytes();

        let our_fvk = our_orchard_fvk(seed, *coin_type, *account);

        // FVK bytes must match (pre-requisite for encoding to match)
        assert_eq!(
            our_fvk.ak,
            &upstream_bytes[..32],
            "ak mismatch for vector {i}"
        );
        assert_eq!(
            our_fvk.nk,
            &upstream_bytes[32..64],
            "nk mismatch for vector {i}"
        );
        assert_eq!(
            our_fvk.rivk,
            &upstream_bytes[64..96],
            "rivk mismatch for vector {i}"
        );

        // Now encode using upstream bytes directly and compare
        let mainnet = *coin_type == 133;
        let ref_from_upstream = reference_orchard_ufvk(
            upstream_bytes[..32].try_into().unwrap(),
            upstream_bytes[32..64].try_into().unwrap(),
            upstream_bytes[64..96].try_into().unwrap(),
            mainnet,
        );
        let our_encoded = our_orchard_ufvk_string(&our_fvk, mainnet);

        assert_eq!(
            our_encoded, ref_from_upstream,
            "UFVK encoding from upstream FVK bytes differs for vector {i}"
        );
    }
}

/// Verify different seeds/accounts produce different UFVK strings (sanity check).
#[test]
fn different_seeds_produce_different_ufvks() {
    let vectors = test_vectors();

    // Compare first two vectors (same seed, different accounts)
    let fvk0 = our_orchard_fvk(&vectors[0].0, vectors[0].1, vectors[0].2);
    let fvk1 = our_orchard_fvk(&vectors[1].0, vectors[1].1, vectors[1].2);

    let ufvk0 = our_orchard_ufvk_string(&fvk0, true);
    let ufvk1 = our_orchard_ufvk_string(&fvk1, true);

    assert_ne!(
        ufvk0, ufvk1,
        "Different accounts should produce different UFVKs"
    );

    // Compare different seeds (vectors 0 and 4)
    let fvk4 = our_orchard_fvk(&vectors[4].0, vectors[4].1, vectors[4].2);
    let ufvk4 = our_orchard_ufvk_string(&fvk4, true);

    assert_ne!(
        ufvk0, ufvk4,
        "Different seeds should produce different UFVKs"
    );
}
