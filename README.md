# zcash-signer

Minimal Zcash signing primitives for watchOS. This crate provides the cryptographic operations needed for Orchard PCZT (Partially Created Zcash Transaction) signing on Apple Watch.

## Features

- **ZIP-32 Orchard key derivation** - Derive spending keys and `ask` from BIP-39 seeds
- **ZIP-32 Sapling key derivation** - Derive Sapling spending keys and `ask` for legacy shielded funds
- **RedPallas randomized signing** - Sign Orchard spends with alpha randomizers for PCZT
- **RedJubjub randomized signing** - Sign Sapling spends with alpha randomizers for PCZT
- **Combined UFVK generation** - Produce Unified Full Viewing Keys with Transparent + Sapling + Orchard
- **BIP-44 transparent addresses** - Derive t-addresses for CEX compatibility
- **`no_std` compatible** - Runs on watchOS tier-3 targets (arm64, arm64_32)

## Building

### Prerequisites

- Rust nightly toolchain
- Xcode Command Line Tools

```bash
# Install nightly
rustup install nightly

# Build for all Apple platforms
./build-xcframework.sh
```

This creates:
- `target/watchos-device-universal/libzcash_signer.a` (arm64 + arm64_32)
- `target/watchos-sim-universal/libzcash_signer.a` (arm64 + x86_64)
- `target/ios-device/libzcash_signer.a`
- `target/ios-sim-universal/libzcash_signer.a`
- `target/macos-universal/libzcash_signer.a`
- `ZcashSigner.xcframework/`

## Integration

### Option 1: Local Swift Package (Recommended)

1. Add the package to your Xcode project:
   - File → Add Package Dependencies → Add Local → select `zcash-signer` directory

2. Add to your target's **Build Settings**:
   ```
   OTHER_LDFLAGS = -lzcash_signer

   LIBRARY_SEARCH_PATHS[sdk=watchos*] = $(PROJECT_DIR)/../zcash-signer/target/watchos-device-universal
   LIBRARY_SEARCH_PATHS[sdk=watchsimulator*] = $(PROJECT_DIR)/../zcash-signer/target/watchos-sim-universal
   LIBRARY_SEARCH_PATHS[sdk=iphoneos*] = $(PROJECT_DIR)/../zcash-signer/target/ios-device
   LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*] = $(PROJECT_DIR)/../zcash-signer/target/ios-sim-universal
   ```

3. Import in Swift:
   ```swift
   import ZcashSignerCore
   ```

### Option 2: Direct Static Library

1. Copy the appropriate `.a` file to your project
2. Add the header search path to `include/`
3. Link against `libzcash_signer.a`

## API Usage

### Key Derivation

```swift
import ZcashSignerCore

// From a BIP-39 seed (64 bytes)
let seed: Data = ... // your mnemonic-derived seed

// Derive Orchard ask (spend authorization key) directly from seed
let orchardAsk = try ZcashOrchardAsk.deriveFromSeed(seed, account: 0)

// Or step-by-step:
let spendingKey = try ZcashOrchardSpendingKey.deriveFromSeed(seed, account: 0)
let orchardAsk = try spendingKey.deriveAsk()

// Derive ak (authorization key) for verification
let ak = try orchardAsk.deriveAk()  // 32 bytes

// Derive Sapling ask for legacy shielded funds
let saplingAsk = try ZcashSaplingAsk.deriveFromSeed(seed, account: 0)

// Derive Sapling ak (authorization key) for verification
let saplingAk = try saplingAsk.deriveAk()  // 32 bytes
```

### PCZT Signing

```swift
// Sign an Orchard spend with alpha randomizer (from PCZT)
let sighash: Data = ...  // 32-byte transaction sighash
let alpha: Data = ...    // 32-byte alpha randomizer from PCZT spend

let orchardSig = try orchardAsk.signRandomized(sighash: sighash, alpha: alpha)
// signature is 64 bytes (R || S)

// Sign a Sapling spend with alpha randomizer
let saplingSig = try saplingAsk.signRandomized(sighash: sighash, alpha: alpha)
// signature is 64 bytes (R || S)
```

### UFVK Derivation

```swift
// Derive combined UFVK (Transparent + Sapling + Orchard)
let ufvk = try deriveCombinedUFVKString(
    seed: seed,
    coinType: ZSIG_MAINNET_COIN_TYPE,
    account: 0,
    mainnet: true
)
// Returns "uview1..." string validated by SDK
```

### Transparent Addresses

```swift
// Derive t-address (BIP-44 path: m/44'/133'/account'/0/index)
let tAddress = try deriveTransparentAddress(
    seed: seed,
    account: 0,
    index: 0,
    mainnet: true
)
// Returns "t1..." string

// Or just the pubkey hash (for Unified Address construction)
let pubkeyHash = try deriveTransparentPubkeyHash(
    seed: seed,
    account: 0,
    index: 0
)
// Returns 20 bytes
```

## FFI Functions

For direct C/Objective-C usage:

### Orchard (RedPallas)

| Function | Description |
|----------|-------------|
| `zsig_derive_orchard_spending_key` | ZIP-32 spending key from seed |
| `zsig_derive_orchard_ask` | Extract ask from spending key |
| `zsig_derive_orchard_ask_from_seed` | Convenience: ask directly from seed |
| `zsig_sign_orchard_randomized` | PCZT signing with alpha randomizer |
| `zsig_sign_orchard` | Non-randomized signing |
| `zsig_verify_orchard` | Signature verification |
| `zsig_derive_ak_from_ask` | Derive authorization key |
| `zsig_derive_orchard_full_viewing_key` | Derive Orchard FVK (ak, nk, rivk) |

### Sapling (RedJubjub)

| Function | Description |
|----------|-------------|
| `zsig_derive_sapling_spending_key` | ZIP-32 spending key from seed |
| `zsig_derive_sapling_ask` | Extract ask from spending key |
| `zsig_derive_sapling_ask_from_seed` | Convenience: ask directly from seed |
| `zsig_sign_sapling_randomized` | PCZT signing with alpha randomizer |
| `zsig_sign_sapling` | Non-randomized signing |
| `zsig_verify_sapling` | Signature verification |
| `zsig_derive_sapling_ak_from_ask` | Derive authorization key |
| `zsig_derive_sapling_full_viewing_key` | Derive Sapling FVK (ak, nk, ovk, dk) |

### Transparent (secp256k1)

| Function | Description |
|----------|-------------|
| `zsig_derive_transparent_address` | BIP-44 t-address string |
| `zsig_derive_transparent_pubkey_hash` | BIP-44 pubkey hash (20 bytes) |
| `zsig_derive_transparent_fvk` | BIP-44 extended pubkey (chain code + pubkey) |
| `zsig_sign_transparent` | Sign transparent input (DER signature) |

### UFVK (ZIP-316)

| Function | Description |
|----------|-------------|
| `zsig_derive_combined_ufvk_string` | Derive full UFVK (Transparent + Sapling + Orchard) |
| `zsig_encode_unified_full_viewing_key` | Encode Orchard-only FVK as UFVK |
| `zsig_encode_combined_ufvk` | Encode combined FVK as UFVK |

## Architecture Notes

### Why This Exists

The upstream `orchard` and `sapling-crypto` crates' ZIP-32 key derivation requires `std`, which isn't available on watchOS (tier-3 target). This crate implements the same algorithms using `no_std`-compatible primitives:

- `reddsa` for RedPallas (Orchard) and RedJubjub (Sapling) signatures
- `pasta_curves` for Pallas scalar/point operations (Orchard)
- `jubjub` for Jubjub scalar/point operations (Sapling)
- `blake2b_simd` (vendored) for ZIP-32 PRF^expand
- `sinsemilla` for IVK derivation
- `k256` for secp256k1 operations (transparent)

### Signing Flow

```
Phone (SDK)                          Watch (this crate)
─────────────────────────────────────────────────────────
1. Build PCZT with:
   - Transaction structure
   - Alpha randomizers
   - Sighash
                    ──────────────►
                                     2. For each Orchard spend:
                                        ask_rand = ask + alpha
                                        sig = RedPallas::sign(ask_rand, sighash)

                                     3. For each Sapling spend:
                                        ask_rand = ask + alpha
                                        sig = RedJubjub::sign(ask_rand, sighash)

                                     4. For each transparent input:
                                        sig = ECDSA::sign_prehash(privkey, sighash)
                    ◄──────────────
5. Apply signatures to PCZT
6. Generate zk-SNARK proofs
7. Broadcast transaction
```

### Vendor Patches

The `vendor/` directory contains patched versions of:

- **blake2b_simd** - Disabled `std` feature (CPU detection hangs on watchOS simulator)
- **constant_time_eq** - Fixed arm64_32 NEON code (upstream uses hardcoded u64 for pointers)

## Testing

```bash
# Run on macOS (uses macos-universal library)
cd /path/to/zcash-signer
swift test
```

## Security

- Keys are never logged or persisted by this library
- RNG is provided via callback (use `SecRandomCopyBytes` on Apple platforms)
- All operations use constant-time implementations where available

## PCZT Workflow with pczt-cli

The `pczt-cli` tool demonstrates the complete PCZT (Partially Created Zcash Transaction) workflow, simulating the phone + watch signing flow.

### Prerequisites

```bash
# Set your BIP-39 seed (24 words or 64-byte hex)
export ZCASH_SEED="your twenty four word mnemonic phrase here ..."

# Build the CLI
swift build --product pczt-cli
```

### Complete Shielding Flow

```bash
# 1. Initialize wallet (derives UFVK for phone, ASK for watch)
pczt-cli init
# Outputs: { "ufvk": "uview1...", "ask": "abc123..." }

# 2. Sync with lightwalletd
pczt-cli sync

# 3. Create shielding proposal (transparent → Orchard)
pczt-cli propose shield 100000
# Outputs: { "proposal_id": "..." }

# 4. Create PCZT from proposal
pczt-cli create-pczt <proposal_id>
# Outputs: { "pczt_file": "~/.pczt-cli/pczts/pczt_xxx.bin" }

# 5. Extract sighashes (what the watch needs to sign)
pczt-cli extract-sighashes <pczt_file> > sighashes.json

# 6. Sign on watch (simulated - uses ASK for Orchard, ZCASH_SEED for transparent)
pczt-cli sign <ask> sighashes.json > signatures.json

# 7. Apply signatures back to PCZT
pczt-cli apply-signatures <pczt_file> signatures.json
# Outputs: { "pczt_file": "~/.pczt-cli/pczts/pczt_xxx_signed.bin" }

# 8. Generate zk-SNARK proofs (phone)
pczt-cli prove <pczt_file>
# Outputs: { "pczt_file": "~/.pczt-cli/pczts/pczt_xxx_proven.bin" }

# 9. Broadcast (combines proven + signed PCZTs)
pczt-cli broadcast <proven_pczt> <signed_pczt>
# Outputs: { "success": true, "txid": "267a2d9e..." }
```

### Key Insights for PCZT Integration

1. **Dummy Orchard Spends**: Shielding transactions have dummy Orchard spends (no real inputs). These are signed during IO Finalization with an internal key. Check `alreadySigned` field and skip signing these.

2. **Transparent Signature Format**: The signature must be `<DER_encoded_sig || sighash_type_byte>`. Don't forget to append `0x01` (SIGHASH_ALL) to the DER signature.

3. **Pre-hashed Signing**: The sighash is already a 32-byte hash. Use `sign_prehash()` (not `sign()`) to avoid double-hashing.

4. **Split Sign/Prove Flow**: Signatures and proofs can be generated independently and combined at broadcast time. This enables the watch to sign while the phone generates proofs in parallel.

### Sighashes JSON Format

```json
{
  "shielded_sighash": "902f7029...",
  "orchard_spends": [
    {
      "index": 0,
      "randomizer": "4c75483a...",
      "rk": "abc123...",
      "already_signed": true
    }
  ],
  "sapling_spends": [
    {
      "index": 0,
      "randomizer": "5d86594b...",
      "rk": "def456...",
      "already_signed": false
    }
  ],
  "transparent_inputs": [
    {
      "index": 0,
      "sighash": "5cc4bafe...",
      "sighash_type": 1,
      "derivation_path": [2147483692, 2147483781, 2147483648, 0, 0],
      "script_pub_key": "76a914...",
      "value": 2693748
    }
  ]
}
```

### Signatures JSON Format

```json
{
  "orchard_signatures": [
    { "index": 0, "signature": "64-byte-hex" }
  ],
  "sapling_signatures": [
    { "index": 0, "signature": "64-byte-hex" }
  ],
  "transparent_signatures": [
    {
      "index": 0,
      "signature": "DER-sig-with-hashtype-hex",
      "public_key": "33-byte-compressed-pubkey-hex",
      "sighash_type": 1
    }
  ]
}
```

## License

MIT
