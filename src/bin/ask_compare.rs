use std::env;
use std::process::exit;

use bip39::{Language, Mnemonic};
use ff::PrimeField;
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use pasta_curves::pallas::Scalar as PallasScalar;
use zip32::AccountId;

use zcash_signer::{
    zsig_derive_orchard_ask, zsig_derive_orchard_ask_from_seed,
    zsig_derive_orchard_spending_key, ZsigError, ZsigOrchardAsk, ZsigOrchardSpendingKey,
};

fn main() {
    let mut args = env::args().skip(1);
    let seed_hex = match args.next() {
        Some(value) => value,
        None => env::var("ZCASH_SEED").unwrap_or_else(|_| {
            eprintln!("missing seed: pass hex seed or set ZCASH_SEED");
            exit(2);
        }),
    };

    let account: u32 = args
        .next()
        .as_deref()
        .unwrap_or("0")
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("invalid account index");
            exit(2);
        });

    let coin_type: u32 = args
        .next()
        .as_deref()
        .unwrap_or("133")
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("invalid coin type");
            exit(2);
        });

    let alpha_hex = args.next();

    let seed = parse_seed(&seed_hex).unwrap_or_else(|err| {
        eprintln!("seed parse failed: {err}");
        exit(2);
    });

    let mut zsig_sk = ZsigOrchardSpendingKey { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_orchard_spending_key(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut zsig_sk,
        )
    };
    ensure_success("zsig_derive_orchard_spending_key", err);

    let mut zsig_ask = ZsigOrchardAsk { bytes: [0u8; 32] };
    let err = unsafe { zsig_derive_orchard_ask(&zsig_sk, &mut zsig_ask) };
    ensure_success("zsig_derive_orchard_ask", err);

    let mut zsig_ask_from_seed = ZsigOrchardAsk { bytes: [0u8; 32] };
    let err = unsafe {
        zsig_derive_orchard_ask_from_seed(
            seed.as_ptr(),
            seed.len(),
            coin_type,
            account,
            &mut zsig_ask_from_seed,
        )
    };
    ensure_success("zsig_derive_orchard_ask_from_seed", err);

    let orchard_account = AccountId::try_from(account).unwrap_or_else(|_| {
        eprintln!("account index out of range (must be < 2^31)");
        exit(2);
    });
    let orchard_sk = SpendingKey::from_zip32_seed(&seed, coin_type, orchard_account).unwrap();
    let orchard_ask = SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk: FullViewingKey = (&orchard_sk).into();

    println!("account: {account}");
    println!("coin_type: {coin_type}");
    println!("seed_len: {}", seed.len());
    println!();
    println!("zcash_signer sk : {}", hex_encode(&zsig_sk.bytes));
    println!("orchard sk      : {}", hex_encode(orchard_sk.to_bytes()));
    println!("sk matches      : {}", zsig_sk.bytes == *orchard_sk.to_bytes());
    println!();
    println!("zcash_signer ask: {}", hex_encode(&zsig_ask.bytes));
    println!("orchard ask     : {}", hex_encode(&orchard_ask.to_bytes()));
    println!("ask matches     : {}", zsig_ask.bytes == orchard_ask.to_bytes());
    println!();
    println!("orchard fvk     : {}", hex_encode(&orchard_fvk.to_bytes()));
    println!();
    println!(
        "ask from seed   : {}",
        hex_encode(&zsig_ask_from_seed.bytes)
    );
    println!(
        "ask(seed) match : {}",
        zsig_ask_from_seed.bytes == zsig_ask.bytes
    );

    if let Some(alpha_hex) = alpha_hex {
        let alpha_bytes = decode_hex(alpha_hex.trim_start_matches("0x")).unwrap_or_else(|err| {
            eprintln!("alpha hex decode failed: {err}");
            exit(2);
        });
        if alpha_bytes.len() != 32 {
            eprintln!("alpha must be 32 bytes");
            exit(2);
        }
        let alpha_scalar =
            PallasScalar::from_repr(alpha_bytes.as_slice().try_into().unwrap());
        let alpha_scalar = Option::<PallasScalar>::from(alpha_scalar).unwrap_or_else(|| {
            eprintln!("alpha is not a valid pallas scalar");
            exit(2);
        });
        let rsk = orchard_ask.randomize(&alpha_scalar);
        let rk = VerificationKey::<SpendAuth>::from(&rsk);
        let rk_bytes: [u8; 32] = rk.into();
        println!();
        println!("rk(ask,alpha)  : {}", hex_encode(&rk_bytes));
    }
}

fn ensure_success(label: &str, err: ZsigError) {
    if err != ZsigError::Success {
        eprintln!("{label} failed: {err:?}");
        exit(1);
    }
}

fn parse_seed(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.contains(char::is_whitespace) {
        let mnemonic = Mnemonic::parse_in(Language::English, trimmed)
            .map_err(|err| format!("mnemonic parse failed: {err}"))?;
        Ok(mnemonic.to_seed("").to_vec())
    } else {
        decode_hex(trimmed.trim_start_matches("0x"))
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let Some(high) = chars.next() {
        let low = chars.next().ok_or("odd-length hex")?;
        let value = hex_value(high)? << 4 | hex_value(low)?;
        bytes.push(value);
    }
    Ok(bytes)
}

fn hex_value(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(format!("invalid hex char: {c}")),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}
