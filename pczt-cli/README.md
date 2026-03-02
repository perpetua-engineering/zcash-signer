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
| `address` | Derive and display addresses |
| `propose` | Create a shielding or transfer proposal → base PCZT |
| `sign` | Sign a PCZT binary (derives keys from seed, signs all pools) |
| `prove` | Add zk-SNARK proofs to PCZT |
| `broadcast` | Submit proven+signed PCZT to network (fork-merge flow) |
| `send` | Complete and broadcast signed PCZT (sequential flow) |
| `inspect` | Show PCZT summary and state |
| `test-ufvk` | Validate Rust UFVK derivation against SDK |
| `compare-address` | Compare address derivation against SDK |

## Workflow Patterns

### Sequential Flow (Recommended)

Sign first, then prove and broadcast in one step. The `sign` command derives all keys
from `ZCASH_SEED` and signs the PCZT directly — no sighash extraction needed.

```bash
# 1. Initialize and sync
export ZCASH_SEED="your 24 word mnemonic here"
pczt-cli init
pczt-cli sync

# 2. Create proposal (base PCZT)
pczt-cli propose shield 100000

# 3. Sign PCZT (derives keys from seed, signs all pools)
pczt-cli sign ~/.pczt-cli/pczts/pczt_XXXX.bin

# 4. Add proofs and broadcast
pczt-cli send ~/.pczt-cli/pczts/pczt_XXXX_signed.bin
```

### Fork-Merge Flow

Prove and sign independently, then merge at broadcast. Can cause
`OrchardBindingSigMismatch` if PCZTs diverge — prefer sequential flow.

```bash
# 1-2. Same as above

# 3. Sign the base PCZT
pczt-cli sign ~/.pczt-cli/pczts/pczt_XXXX.bin

# 4. Prove the base PCZT (separate copy)
pczt-cli prove ~/.pczt-cli/pczts/pczt_XXXX.bin

# 5. Broadcast with both
pczt-cli broadcast ~/.pczt-cli/pczts/pczt_XXXX_proven.bin ~/.pczt-cli/pczts/pczt_XXXX_signed.bin
```

## The OrchardBindingSigMismatch Problem

This error occurs when:
1. Proofs and signatures are generated from different PCZT states
2. The binding signature (bsk) doesn't match the value commitments

**Root cause**: The Prover modifies PCZT state when adding proofs. If you fork the PCZT
into two copies and modify them independently, they diverge and cannot be merged.

**Solution**: Use the sequential flow (`send` command) which applies signatures, then
proofs, then broadcasts from a single consistent PCZT.

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

## License

MIT
