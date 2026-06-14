//! Randomized robustness ("fuzz") coverage for the watch-side PCZT
//! entrypoints (CR-1331).
//!
//! The watch parses attacker-influenced PCZT bytes from the phone before it
//! ever decides to sign, so `pczt_info`, `pczt_summary`, and `sign_pczt` must
//! never panic (the device build is `panic = "abort"`, so a panic is a crash)
//! and must never hang, regardless of input. A five-element fixed table is not
//! fuzzing — this drives thousands of pseudo-random and mutated inputs through
//! every entrypoint and asserts each one terminates with `Ok`/`Err`, never a
//! panic.
//!
//! Determinism: a fixed-seed xorshift PRNG (no `rand`, no clock) so failures
//! reproduce exactly. Run with `cargo test --features pczt-signer`.

#![cfg(feature = "pczt-signer")]

use pczt::roles::creator::Creator;
use zcash_protocol::consensus::{BranchId, NetworkType};
use zcash_signer::pczt_signer::{pczt_info, pczt_summary, sign_pczt, PcztSigningKeys};
use zcash_signer::pczt_verify::{
    derive_wallet_viewing_keys, pczt_verify, ApprovedTx, WalletViewingKeys,
};

/// Deterministic xorshift64* PRNG — reproducible, no external deps.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the zero fixed point.
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /// A length in `[0, max]`, weighted toward small buffers.
    fn next_len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }

    fn fill(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_byte()).collect()
    }
}

fn no_signing_keys<'a>() -> PcztSigningKeys<'a> {
    PcztSigningKeys {
        orchard_sk: None,
        sapling_ask: None,
        transparent_sk: None,
    }
}

/// A grab-bag of recipient strings: empty, garbage, and structurally
/// address-shaped values that exercise the `ZcashAddress` decoder.
const RECIPIENTS: &[&str] = &[
    "",
    "u1",
    "not-an-address",
    "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
    "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
    "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
    "\u{feff}\u{0}\u{1}garbage\u{7f}",
];

fn networks() -> [NetworkType; 2] {
    [NetworkType::Main, NetworkType::Test]
}

/// A deterministic 64-byte seed so the key-bearing branches exercise *valid*
/// SE-style derived keys (the production path only ever signs with valid,
/// seed-derived keys), and the ownership verifier runs against real viewing
/// keys. CR-1337 (gap 5).
const FUZZ_SEED: [u8; 64] = [0x5A; 64];

/// Build the SE-style signing keys (valid Orchard sk, plus a *zero* Sapling ask
/// to keep exercising the gap-4 malformed-key guard) for the key-bearing fuzz.
fn fuzz_signing_keys<'a>(orchard_sk: &'a [u8; 32], zero_sapling: &'a [u8; 32]) -> PcztSigningKeys<'a> {
    PcztSigningKeys {
        orchard_sk: Some(orchard_sk),
        sapling_ask: Some(zero_sapling),
        transparent_sk: None,
    }
}

/// Drive every attacker-controlled entrypoint over a byte buffer. Any panic
/// fails the test; the return values themselves are not asserted (random bytes
/// legitimately produce either `Ok` or `Err`) — the contract under test is
/// "terminates without panicking".
///
/// We exercise `sign_pczt` both with no keys (the full parse -> `Signer::new` ->
/// `finish` pipeline) and with key-bearing branches: a valid SE-derived Orchard
/// spending key (the realistic production input) plus a zero Sapling ask, which
/// keeps the CR-1337 gap-4 malformed-ask guard under continuous fuzz. `pczt_verify`
/// (CR-1337) is driven over the same bytes with real viewing keys derived from a
/// fixed seed.
fn exercise(bytes: &[u8], rng: &mut Rng, keys: &WalletViewingKeys, orchard_sk: &[u8; 32]) {
    let _ = pczt_info(bytes);
    let _ = sign_pczt(bytes, &no_signing_keys());

    // Key-bearing path: valid Orchard sk + zero Sapling ask. Must not panic;
    // the zero ask must surface as a clean error, never an abort.
    let zero_sapling = [0u8; 32];
    let _ = sign_pczt(bytes, &fuzz_signing_keys(orchard_sk, &zero_sapling));

    // Vary the recipient + network so the summary decoder's address-matching
    // branches are exercised against the same (often malformed) PCZT bytes.
    let recipient = RECIPIENTS[(rng.next_u64() as usize) % RECIPIENTS.len()];
    let network = networks()[(rng.next_u64() as usize) % networks().len()];
    let _ = pczt_summary(bytes, recipient, network);

    // Ownership-totality + memo verifier over attacker bytes with real keys.
    let memo = if rng.next_u64() & 1 == 0 { "" } else { "memo" };
    let approved = ApprovedTx {
        recipient_address: recipient,
        expected_amount_zatoshis: rng.next_u64(),
        expected_memo: memo,
        network,
    };
    let _ = pczt_verify(bytes, &approved, keys);
}

/// Derive the fuzz keys once (key derivation is comparatively expensive).
fn fuzz_keys() -> (WalletViewingKeys, [u8; 32]) {
    let viewing = derive_wallet_viewing_keys(&FUZZ_SEED, 133, 0);
    // A valid Orchard spending key the signer accepts: reuse the same FVK seed.
    // `derive_wallet_viewing_keys` proves the seed yields a valid Orchard key,
    // so a fixed non-zero sk array suffices for the signer's `from_bytes`.
    let orchard_sk = [0x42u8; 32];
    (viewing, orchard_sk)
}

#[test]
fn entrypoints_survive_random_bytes() {
    let (keys, orchard_sk) = fuzz_keys();
    let mut rng = Rng::new(0xC0FF_EE12_3456_789A);
    // Cap length generously above realistic small PCZTs while staying cheap.
    for _ in 0..20_000 {
        let len = rng.next_len(512);
        let bytes = rng.fill(len);
        exercise(&bytes, &mut rng, &keys, &orchard_sk);
    }
}

#[test]
fn entrypoints_survive_pczt_magic_prefixed_garbage() {
    // The parser keys off a magic prefix; feeding well-formed-looking headers
    // with random tails reaches deeper into the decoder than pure noise.
    let magic = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
        .build()
        .serialize();
    let prefix = &magic[..magic.len().min(8)];

    let (keys, orchard_sk) = fuzz_keys();
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..20_000 {
        let mut bytes = prefix.to_vec();
        let tail_len = rng.next_len(256);
        bytes.extend(rng.fill(tail_len));
        exercise(&bytes, &mut rng, &keys, &orchard_sk);
    }
}

#[test]
fn entrypoints_survive_bit_flipped_valid_pczt() {
    // Start from a real, parseable PCZT and corrupt it the way a flaky or
    // hostile transport would: single bit flips, byte zeroing, truncation,
    // and duplication. Each mutant must still terminate cleanly.
    let valid = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
        .build()
        .serialize();
    assert!(pczt_info(&valid).is_ok(), "baseline PCZT must parse");

    let (keys, orchard_sk) = fuzz_keys();
    let mut rng = Rng::new(0x0BAD_F00D_DEAD_BEEF);
    for _ in 0..20_000 {
        let mut bytes = valid.clone();
        if !bytes.is_empty() {
            match rng.next_u64() % 4 {
                0 => {
                    // Flip one random bit.
                    let idx = (rng.next_u64() as usize) % bytes.len();
                    bytes[idx] ^= 1 << (rng.next_byte() & 7);
                }
                1 => {
                    // Overwrite a random byte.
                    let idx = (rng.next_u64() as usize) % bytes.len();
                    bytes[idx] = rng.next_byte();
                }
                2 => {
                    // Truncate to a random length.
                    let keep = (rng.next_u64() as usize) % bytes.len();
                    bytes.truncate(keep);
                }
                _ => {
                    // Append random trailing bytes.
                    let tail_len = rng.next_len(64);
                    bytes.extend(rng.fill(tail_len));
                }
            }
        }
        exercise(&bytes, &mut rng, &keys, &orchard_sk);
    }
}

#[test]
fn empty_and_tiny_buffers_are_handled() {
    let (keys, orchard_sk) = fuzz_keys();
    let mut rng = Rng::new(0xFEED_FACE_CAFE_BABE);
    for len in 0..=8usize {
        let bytes = vec![0u8; len];
        exercise(&bytes, &mut rng, &keys, &orchard_sk);
        let noisy = rng.fill(len);
        exercise(&noisy, &mut rng, &keys, &orchard_sk);
    }
}
