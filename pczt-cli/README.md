# pczt-cli

CLI tool for Zcash PCZT (Partially Created Zcash Transaction) workflows. Simulates the phone+watch wallet flow with separate invocations for each step.

## Purpose

This tool helps develop and debug PCZT-based signing flows, particularly for external signer scenarios like:
- Phone (view-only wallet) + Watch (signing device) architectures
- Hardware wallet integration
- Any flow where key material is isolated from the wallet

## Installation

```bash
swift build --product pczt-cli
```

## Environment Variables

- `ZCASH_SEED` - BIP-39 mnemonic (24 words) or 64-byte hex seed
- `ZCASH_UFVK` - Unified Full Viewing Key (optional, derived from seed if not set)
- `ZCASH_BIRTHDAY` - Wallet birthday block height (default: 2657762)
- `ZCASH_LIGHTWALLETD` - Lightwalletd URL (default: https://zec.rocks:443)
- `ZCASH_NETWORK` - Network: mainnet or testnet (default: mainnet)

## Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize wallet from seed, derive keys, save config |
| `sync` | Sync wallet with the blockchain |
| `propose` | Create a shielding or transfer proposal → base PCZT |
| `extract-sighashes` | Extract sighashes from PCZT for signing |
| `sign` | Sign sighashes with ASK (Orchard/Sapling) and seed (transparent) |
| `apply-signatures` | Apply signatures to PCZT |
| `prove` | Add zk-SNARK proofs to PCZT |
| `broadcast` | Submit proven+signed PCZT to network (fork-merge flow) |
| `send` | Complete and broadcast signed PCZT (sequential flow) |
| `inspect` | Show PCZT summary and state |
| `test-ufvk` | Validate Rust UFVK derivation against SDK |

## Workflow Patterns

### Sequential Flow (Recommended)

Sign first, then prove. Avoids `OrchardBindingSigMismatch` errors.

```bash
# 1. Initialize and sync
export ZCASH_SEED="your 24 word mnemonic here"
pczt-cli init
pczt-cli sync

# 2. Create proposal (base PCZT)
pczt-cli propose shield 100000

# 3. Extract sighashes from BASE PCZT
pczt-cli extract-sighashes ~/.pczt-cli/pczts/pczt_XXXX.bin > sighashes.json

# 4. Sign (on watch/secure device)
pczt-cli sign <ASK_HEX> sighashes.json > signatures.json

# 5. Apply signatures to BASE PCZT
pczt-cli apply-signatures ~/.pczt-cli/pczts/pczt_XXXX.bin signatures.json

# 6. Add proofs and broadcast (sequential)
pczt-cli send ~/.pczt-cli/pczts/pczt_XXXX_signed.bin
```

### Fork-Merge Flow (Problematic)

Prove first, then sign. Can cause `OrchardBindingSigMismatch` if not careful.

```bash
# 1-2. Same as above

# 3. Add proofs to base PCZT
pczt-cli prove ~/.pczt-cli/pczts/pczt_XXXX.bin

# 4. Extract sighashes from PROVEN PCZT (important!)
pczt-cli extract-sighashes ~/.pczt-cli/pczts/pczt_XXXX_proven.bin > sighashes.json

# 5. Sign
pczt-cli sign <ASK_HEX> sighashes.json > signatures.json

# 6. Apply signatures to PROVEN PCZT (same one used for sighashes!)
pczt-cli apply-signatures ~/.pczt-cli/pczts/pczt_XXXX_proven.bin signatures.json

# 7. Broadcast with both PCZTs
pczt-cli broadcast ~/.pczt-cli/pczts/pczt_XXXX_proven.bin ~/.pczt-cli/pczts/pczt_XXXX_signed.bin
```

## The OrchardBindingSigMismatch Problem

This error occurs when:
1. Proofs and signatures are generated from different PCZT states
2. The binding signature (bsk) doesn't match the value commitments

**Root cause**: The Prover modifies PCZT state when adding proofs. If you:
- Fork the PCZT into two copies
- Add proofs to copy A
- Sign copy B
- Try to merge A + B

The binding signature won't match because A and B diverged.

**Solution**: Use the sequential flow (`send` command) which:
1. Applies signatures to the base PCZT
2. Adds proofs to the signed PCZT
3. Extracts and broadcasts from a single consistent PCZT

## Diagnostic Mode

When broadcast fails, use `--diagnose` to compare PCZT states:

```bash
pczt-cli broadcast --diagnose proven.bin signed.bin
```

This will show:
- PCZT summaries for both files
- Shielded sighash comparison
- Orchard randomizer comparison
- Transparent sighash comparison
- Attempt sequential extraction as a test

## Data Directory

All state is stored in `~/.pczt-cli/`:

```
~/.pczt-cli/
├── config.json          # Wallet configuration
├── data/                # SDK databases
│   └── mainnet/
├── proposals/           # Serialized proposals (if needed)
└── pczts/               # PCZT binary files
```

## Example: Full Shielding Flow

```bash
# Setup
export ZCASH_SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
pczt-cli init
pczt-cli sync

# Create shielding proposal (shield all transparent with threshold 100000 zatoshi)
pczt-cli propose shield 100000
# Output: pczt_file: ~/.pczt-cli/pczts/pczt_abc123.bin

# Extract sighashes
pczt-cli extract-sighashes ~/.pczt-cli/pczts/pczt_abc123.bin 2>/dev/null > /tmp/sighashes.json

# Get ASK from init output, or:
# pczt-cli init 2>&1 | grep "Orchard ASK"

# Sign with ASK
pczt-cli sign e3f28a6fe609a23c85f7260964633802884621b764bd39e581124eaac63b7b12 /tmp/sighashes.json 2>/dev/null > /tmp/signatures.json

# Apply signatures
pczt-cli apply-signatures ~/.pczt-cli/pczts/pczt_abc123.bin /tmp/signatures.json

# Complete and broadcast (adds proofs + sends)
pczt-cli send ~/.pczt-cli/pczts/pczt_abc123_signed.bin
```

## Inspecting PCZTs

```bash
pczt-cli inspect ~/.pczt-cli/pczts/pczt_abc123.bin
```

Output shows:
- Transaction version and consensus branch
- Transparent inputs/outputs and signature counts
- Sapling spends/outputs, anchor, value sum, bsk presence
- Orchard actions, anchor, flags, value sum, bsk presence, signature counts

## Testing UFVK Derivation

The `test-ufvk` command validates that our Rust UFVK derivation produces valid UFVKs:

```bash
ZCASH_SEED="your seed here" pczt-cli test-ufvk
```

This command:
1. Derives a UFVK using the SDK (reference implementation)
2. Derives a UFVK using the Rust library (Transparent + Sapling + Orchard)
3. Validates the Rust UFVK using the SDK's `isValidUnifiedFullViewingKey`
4. Derives a unified address from the Rust UFVK to confirm it's usable

Expected output:
```
[Test] isValidUnifiedFullViewingKey: true
[Test] Derived UA from Rust UFVK: u1...
[Test] SUCCESS: Rust UFVK validated by SDK!
```

The UFVKs may differ in string encoding (receiver ordering, etc.) but both should be valid and derive the same addresses.

## License

MIT
