# PCZT Debugging Notes

## Current Situation
- `pczt-cli` flow for `propose shield` -> sign -> apply -> prove -> broadcast fails with `Pczt(Extraction(OrchardBindingSigMismatch))` during extraction.
- PCZT summaries and extracted sighashes match between proven and signed PCZTs.
- The mismatch persists even when running sequential flow (signed -> prove -> extract).
- Orchard signatures from `ZcashSignerCore` do not match signatures from the SDK reference signer.
- Even with SDK reference signatures applied, extraction still fails.

## Instrumentation Added
- `pczt-cli broadcast --diagnose` prints:
  - PCZT summaries for proven and signed
  - extracted sighashes (shielded, orchard randomizers, transparent)
  - local extract attempts (split and sequential)
  - file: `pczt-cli/Commands/BroadcastCommand.swift`
- Debug extract helpers in SDK:
  - `debugExtractTxFromPCZT`
  - `debugExtractTxFromSignedAndProvenPCZT`
  - file: `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Synchronizer/SDKSynchronizer.swift`
- CLI wrapper for debug extract:
  - file: `pczt-cli/Wallet/WalletManager.swift`
- `extract-sighashes` now includes `script_pub_key`.
  - files: `pczt-cli/Commands/ExtractSighashesCommand.swift`, `pczt-cli/Utils/StateManager.swift`
- Transparent signing respects `sighashType` and logs default path usage if path missing.
  - file: `pczt-cli/Commands/SignCommand.swift`
- `pczt-cli sign --signer compare` loads SDK reference signer dylib and compares signatures.
  - file: `pczt-cli/Commands/SignCommand.swift`
- Added UFVK consistency check during signing (seed-derived vs saved wallet config).
  - file: `pczt-cli/Commands/SignCommand.swift`
- Added `ask_compare` Rust helper (feature-gated) to compare Orchard ZIP-32 keys between `zcash_signer` and `orchard`.
  - file: `src/bin/ask_compare.rs`
- `zcashlc_extract_sighashes_from_pczt` now emits Orchard `rk` per action in JSON (extra field).
  - file: `../zcash-light-client-ffi/rust/src/lib.rs`
- `ask_compare` now accepts mnemonic or hex seeds and can emit `rk(ask, alpha)` when an alpha is provided.
  - file: `src/bin/ask_compare.rs`
- Swift FFI decode now passes through Orchard `rk`, and `pczt-cli extract-sighashes` emits it in JSON.
  - files: `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Transaction/ExternalSignerTypes.swift`,
    `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Rust/ZcashRustBackend.swift`,
    `pczt-cli/Commands/ExtractSighashesCommand.swift`,
    `pczt-cli/Utils/StateManager.swift`
- Added optional `dummy` flag and ZIP-32 derivation passthrough for Orchard spends (if present).
  - files: `../zcash-light-client-ffi/rust/src/lib.rs`,
    `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Transaction/ExternalSignerTypes.swift`,
    `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Rust/ZcashRustBackend.swift`,
    `pczt-cli/Commands/ExtractSighashesCommand.swift`,
    `pczt-cli/Utils/StateManager.swift`
- Added optional Orchard `fvk` passthrough per spend (if present) and print in `ask_compare`.
  - files: `../zcash-light-client-ffi/rust/src/lib.rs`,
    `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Transaction/ExternalSignerTypes.swift`,
    `../zcash-swift-wallet-sdk/Sources/ZcashLightClientKit/Rust/ZcashRustBackend.swift`,
    `pczt-cli/Commands/ExtractSighashesCommand.swift`,
    `pczt-cli/Utils/StateManager.swift`,
    `src/bin/ask_compare.rs`

## Key Findings
- UFVK derived from `ZCASH_SEED` matches the saved wallet config (seed appears consistent).
- Orchard signatures from `ZcashSignerCore` differ from SDK reference signer for the same seed/sighash/randomizer.
- Extraction fails with `OrchardBindingSigMismatch` even when using SDK reference signatures.
- `ask_compare` shows ZIP-32 Orchard `sk` and `ask` match `orchard` for the current seed/account.
- Next: rebuild `zcash-light-client-ffi` to surface `rk` in `extract-sighashes` output, then compare `rk` vs derived `(ask, alpha)`.
  - macOS framework rebuilt and copied into the XCFramework.
- After surfacing `rk`, we compared `rk` from PCZT to `rk(ask, alpha)` and they do not match for either spend index (even with account 0).
- For `pczt_b8b7840d_signed.bin`, `dummy=false` for both Orchard spends and `zip32_derivation` is absent.
- The Orchard `fvk` values embedded in the PCZT spends do not match the `fvk` derived from `ZCASH_SEED` (account 0, coin type 133).

## Working Hypotheses
1) PCZT contains Orchard `rk` values not derived from the seed/alpha we’re using.
2) Signature encoding or verification expectations differ between our signer and the SDK/zcashlc.

## RESOLVED - Root Causes Found (2025-01-22)

After extensive debugging, **three distinct bugs** were identified and fixed:

### Bug 1: Re-signing Already-Signed Dummy Spends (OrchardBindingSigMismatch)

**Root Cause**: For shielding transactions (transparent → Orchard), the PCZT contains **dummy Orchard spends**. During IO Finalization (`IoFinalizer::finalize_io()`), these dummy spends are signed with an internal `dummy_sk`, which is then **cleared**.

Our code checked `dummy_sk().is_some()` to detect dummy spends, but this always returned `false` after IO Finalization. We were re-signing already-signed spends with the wrong key (our `ask` vs the internal `dummy_sk`).

**Fix**: Added `alreadySigned` field that checks `spend_auth_sig().is_some()`. Spends that already have signatures are skipped.

**Files Changed**:
- `zcash-light-client-ffi/rust/src/lib.rs` - Add `already_signed` to JSON output
- `zcash-swift-wallet-sdk/.../ExternalSignerTypes.swift` - Parse `isAlreadySigned`
- `pczt-cli/Commands/SignCommand.swift` - Skip already-signed spends

### Bug 2: Missing Sighash Type Byte (SignatureEncoding DER Error)

**Root Cause**: Bitcoin/Zcash P2PKH scriptSig requires: `<DER_signature || sighash_type_byte>`. We were outputting only the DER signature without appending `0x01` (SIGHASH_ALL).

**Fix**: Append sighash_type byte to the DER signature before output.

**File Changed**: `pczt-cli/Commands/SignCommand.swift`

### Bug 3: Double-Hashing the Sighash (ScriptInvalid)

**Root Cause**: The k256 crate's `sign()` method hashes the input with SHA-256 internally. But our sighash is already a 32-byte hash — we were computing `Sign(SHA256(sighash))` instead of `Sign(sighash)`.

**Fix**: Use `sign_prehash()` instead of `sign()` to sign the pre-hashed message directly.

**File Changed**: `src/transparent.rs`

### Successful Broadcast

After these fixes, the complete PCZT shielding workflow works end-to-end:

```
TxID: 267a2d9eb1f550377cfed5296b7197fa427e476c4951aec2f4db56f413a4addb
```

## Lessons Learned

1. **IO Finalization has side effects**: It signs dummy spends AND clears `dummy_sk`. Checking `dummy_sk` after finalization is useless.

2. **Bitcoin signature format is tricky**: The sighash_type byte must be appended to the DER signature for scriptSig.

3. **Know your crypto library**: `sign()` vs `sign_prehash()` is a critical distinction when working with pre-hashed messages.

4. **Comprehensive logging is essential**: The diagnostic instrumentation added during debugging (PCZT summaries, sighash comparison, signature comparison) was crucial for isolating each bug.

---

## Historical Notes (Pre-Resolution)

### Next Diagnostic Steps (Low-Level) [COMPLETED]
1) Extract Orchard `rk` + `alpha` from the PCZT and verify:
   - derive `rk` from seed + `alpha`
   - compare to PCZT `rk`
   - if mismatch, the PCZT is built for a different key
2) Build a tiny Rust helper to:
   - read PCZT, dump Orchard spend fields
   - compute `rk` and optionally verify spend auth signatures
3) If `rk` matches, compare raw signature bytes produced by:
   - `ZcashSignerCore` (this repo)
   - SDK `Tools/ZcashSigner` dylib
   - ensure both use the same key derivation and signing algorithm
4) Run `ask_compare` against the current seed to see whether our ZIP-32 sk/ask derivation diverges.

---

## Sapling FVK Validation Issue (2025-01-23) [RESOLVED]

### Problem
When generating a combined UFVK (Transparent + Sapling + Orchard), the SDK rejected it with:
```
Invalid key data for key type Sapling
```

### Investigation
1. The UFVK length matched SDK output (510 chars)
2. Transparent and Orchard components validated correctly
3. The Sapling FVK was being rejected during UFVK parsing

### Root Cause
The `SAPLING_PROOF_GEN_KEY_GENERATOR` constant had an incorrect sign bit.

In Jubjub/Edwards curve point encoding:
- The y-coordinate is stored in the first 31.875 bytes
- The sign bit (indicating x-coordinate parity) is in the MSB of the last byte

The x-coordinate of PROOF_GENERATION_KEY_GENERATOR from sapling-crypto:
```rust
x = 0x3af2_dbef_b96e_2571...
```
The LSB of x is `1`, meaning the sign bit should be SET.

**Wrong**: Last byte was `0x54` (sign bit NOT set)
**Correct**: Last byte should be `0xd4` (sign bit SET)

### Fix
Updated `src/address.rs`:
```rust
const SAPLING_PROOF_GEN_KEY_GENERATOR: [u8; 32] = [
    0xe7, 0xe8, 0x5d, 0xe0, 0xf7, 0xf9, 0x7a, 0x46,
    0xd2, 0x49, 0xa1, 0xf5, 0xea, 0x51, 0xdf, 0x50,
    0xcc, 0x48, 0x49, 0x0f, 0x84, 0x01, 0xc9, 0xde,
    0x7a, 0x2a, 0xdf, 0x18, 0x07, 0xd1, 0xb6, 0xd4, // 0xd4 (sign bit set)
];
```

### Verification
Use `pczt-cli test-ufvk` to validate Rust UFVK against SDK:
```bash
ZCASH_SEED="..." pczt-cli test-ufvk
```

Output shows:
- `isValidUnifiedFullViewingKey: true`
- Successfully derived unified address from Rust UFVK
- Both UFVKs have same length (510 chars)

### Lesson Learned
When computing compressed Edwards curve point encodings manually:
1. Convert the y-coordinate to little-endian bytes
2. Determine the sign bit from the x-coordinate's LSB
3. Set the MSB of the last byte if sign bit is 1

Better yet: use the curve library's `to_bytes()` method directly to avoid manual encoding errors.
