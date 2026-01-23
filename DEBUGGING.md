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

## Next Diagnostic Steps (Low-Level)
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
