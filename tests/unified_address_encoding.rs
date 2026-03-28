//! ZIP-316 transparent-enabled Unified Address encoding tests.
//!
//! These tests exercise the Orchard + transparent receiver path directly and
//! verify that we append the 16-byte HRP padding before F4Jumble.

use bech32::{Bech32m, Hrp};

use zcash_signer::{zsig_encode_unified_address_with_transparent, ZsigOrchardAddress};

fn sample_orchard_address() -> ZsigOrchardAddress {
    let mut diversifier = [0u8; 11];
    for (i, byte) in diversifier.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut pk_d = [0u8; 32];
    for (i, byte) in pk_d.iter_mut().enumerate() {
        *byte = 0x40 + i as u8;
    }

    ZsigOrchardAddress { diversifier, pk_d }
}

fn sample_transparent_pkh() -> [u8; 20] {
    let mut pkh = [0u8; 20];
    for (i, byte) in pkh.iter_mut().enumerate() {
        *byte = 0x80 + i as u8;
    }
    pkh
}

fn reference_transparent_unified_address_payload(
    orchard: &ZsigOrchardAddress,
    transparent: &[u8; 20],
    mainnet: bool,
) -> [u8; 83] {
    let hrp = if mainnet { "u" } else { "utest" };

    let mut raw = [0u8; 83];
    raw[0] = 0x00;
    raw[1] = 20;
    raw[2..22].copy_from_slice(transparent);

    raw[22] = 0x03;
    raw[23] = 43;
    raw[24..35].copy_from_slice(&orchard.diversifier);
    raw[35..67].copy_from_slice(&orchard.pk_d);

    let hrp_bytes = hrp.as_bytes();
    raw[67..67 + hrp_bytes.len()].copy_from_slice(hrp_bytes);

    raw
}

fn reference_transparent_unified_address(
    orchard: &ZsigOrchardAddress,
    transparent: &[u8; 20],
    mainnet: bool,
) -> String {
    let hrp_str = if mainnet { "u" } else { "utest" };
    let raw = reference_transparent_unified_address_payload(orchard, transparent, mainnet);
    let jumbled = f4jumble::f4jumble(&raw).expect("f4jumble failed");
    let hrp = Hrp::parse(hrp_str).expect("valid HRP");
    bech32::encode::<Bech32m>(hrp, &jumbled).expect("bech32m encode failed")
}

fn our_transparent_unified_address(
    orchard: &ZsigOrchardAddress,
    transparent: &[u8; 20],
    mainnet: bool,
) -> String {
    let mut buf = [0u8; 256];
    let len = unsafe {
        zsig_encode_unified_address_with_transparent(
            orchard,
            transparent.as_ptr(),
            mainnet,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert!(len > 0, "zsig_encode_unified_address_with_transparent failed");
    String::from_utf8(buf[..len].to_vec()).expect("valid UTF-8")
}

#[test]
fn transparent_unified_address_encoding_matches_reference() {
    let orchard = sample_orchard_address();
    let transparent = sample_transparent_pkh();

    for mainnet in [true, false] {
        let our_ua = our_transparent_unified_address(&orchard, &transparent, mainnet);
        let reference_ua = reference_transparent_unified_address(&orchard, &transparent, mainnet);

        assert_eq!(
            our_ua, reference_ua,
            "transparent-enabled UA encoding mismatch for mainnet={mainnet}"
        );
    }
}

#[test]
fn transparent_unified_address_decodes_to_expected_hrp_padded_payload() {
    let orchard = sample_orchard_address();
    let transparent = sample_transparent_pkh();

    for mainnet in [true, false] {
        let ua = our_transparent_unified_address(&orchard, &transparent, mainnet);
        let (hrp, data) = bech32::decode(&ua).expect("bech32m decode failed");
        let expected_hrp = if mainnet { "u" } else { "utest" };
        assert_eq!(hrp.as_str(), expected_hrp, "HRP mismatch for mainnet={mainnet}");

        let unjumbled = f4jumble::f4jumble_inv(&data).expect("f4jumble_inv failed");
        let expected_payload =
            reference_transparent_unified_address_payload(&orchard, &transparent, mainnet);

        assert_eq!(
            unjumbled.as_slice(),
            &expected_payload,
            "decoded UA payload mismatch for mainnet={mainnet}"
        );

        let mut expected_pad = [0u8; 16];
        expected_pad[..expected_hrp.len()].copy_from_slice(expected_hrp.as_bytes());
        assert_eq!(
            &unjumbled[67..83],
            &expected_pad,
            "ZIP-316 HRP padding mismatch for mainnet={mainnet}"
        );
    }
}
