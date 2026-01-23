//! Diagnostic tool: Verify Orchard randomized verification key (rk) computation
//!
//! Used during PCZT debugging to verify that our ASK produces the expected rk
//! when combined with the randomizer (alpha) from the PCZT.
//!
//! The relationship is: rk = VerificationKey(ask + alpha)
//!
//! If rk doesn't match, the PCZT was created with a different spending key,
//! and signing will fail with OrchardBindingSigMismatch.
//!
//! Usage: verify_rk <ask_hex> <alpha_hex> <expected_rk_hex>

use std::env;
use ff::PrimeField;
use pasta_curves::pallas;
use reddsa::orchard::SpendAuth;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: verify_rk <ask_hex> <alpha_hex> <expected_rk_hex>");
        std::process::exit(1);
    }

    let ask_hex = &args[1];
    let alpha_hex = &args[2];
    let expected_rk_hex = &args[3];

    // Parse ask
    let ask_bytes: [u8; 32] = hex::decode(ask_hex)
        .expect("Invalid ask hex")
        .try_into()
        .expect("ask must be 32 bytes");

    // Parse alpha
    let alpha_bytes: [u8; 32] = hex::decode(alpha_hex)
        .expect("Invalid alpha hex")
        .try_into()
        .expect("alpha must be 32 bytes");

    // Parse expected rk
    let expected_rk_bytes: [u8; 32] = hex::decode(expected_rk_hex)
        .expect("Invalid rk hex")
        .try_into()
        .expect("rk must be 32 bytes");

    // Convert to scalars
    let ask_scalar = pallas::Scalar::from_repr(ask_bytes.into())
        .expect("ask is not a valid scalar");
    let alpha_scalar = pallas::Scalar::from_repr(alpha_bytes.into())
        .expect("alpha is not a valid scalar");

    // Compute rsk = ask + alpha
    let rsk_scalar = ask_scalar + alpha_scalar;
    let rsk_bytes: [u8; 32] = rsk_scalar.to_repr().into();

    println!("ask:    {}", hex::encode(ask_bytes));
    println!("alpha:  {}", hex::encode(alpha_bytes));
    println!("rsk:    {}", hex::encode(rsk_bytes));

    // Convert rsk to signing key and derive verification key (rk)
    let rsk: reddsa::SigningKey<SpendAuth> = reddsa::SigningKey::try_from(rsk_bytes)
        .expect("rsk is not a valid signing key");

    let rk: reddsa::VerificationKey<SpendAuth> = (&rsk).into();
    let rk_bytes: [u8; 32] = rk.into();

    println!("computed rk: {}", hex::encode(rk_bytes));
    println!("expected rk: {}", hex::encode(expected_rk_bytes));

    if rk_bytes == expected_rk_bytes {
        println!("✓ rk MATCHES!");
    } else {
        println!("✗ rk does NOT match!");

        // Also try with negated ask (in case normalization is needed)
        let ask_neg = -ask_scalar;
        let rsk_neg_scalar = ask_neg + alpha_scalar;
        let rsk_neg_bytes: [u8; 32] = rsk_neg_scalar.to_repr().into();

        if let Ok(rsk_neg) = reddsa::SigningKey::<SpendAuth>::try_from(rsk_neg_bytes) {
            let rk_neg: reddsa::VerificationKey<SpendAuth> = (&rsk_neg).into();
            let rk_neg_bytes: [u8; 32] = rk_neg.into();

            println!("with negated ask:");
            println!("  rsk (negated): {}", hex::encode(rsk_neg_bytes));
            println!("  rk (negated):  {}", hex::encode(rk_neg_bytes));

            if rk_neg_bytes == expected_rk_bytes {
                println!("  ✓ rk MATCHES with negated ask!");
            } else {
                println!("  ✗ Still doesn't match");
            }
        }
    }
}
