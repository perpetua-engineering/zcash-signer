# zcash-signer Architecture

This document explains the `no_std` architecture of `zcash-signer` and why each design
choice was made. It is intended for upstream Zcash reviewers and future contributors.

## Why `no_std`?

Apple Watch runs watchOS, which is a **Rust tier-3 target**. The relevant triples are:

| Triple | Description |
|--------|-------------|
| `aarch64-apple-watchos` | Apple Watch Series 4+ (arm64) |
| `arm64_32-apple-watchos` | Apple Watch Series 3 and earlier (arm64 with 32-bit pointers) |
| `aarch64-apple-watchos-sim` | watchOS Simulator on Apple Silicon |
| `x86_64-apple-watchos-sim` | watchOS Simulator on Intel |

Tier-3 targets have no pre-compiled `std`. While `core` and `alloc` can be compiled
from source via `-Z build-std`, the full `std` crate cannot — it depends on
platform-specific I/O, threading, and networking primitives that Rust does not implement
for watchOS.

The upstream `orchard` and `sapling-crypto` crates require `std` (via transitive
dependencies on `getrandom`, `rayon`, and others). Rather than fork the entire Zcash
dependency tree to strip `std`, this crate re-implements only the subset of operations
needed on the watch — key derivation and signing — using `no_std`-compatible primitives.

### What the watch actually does

The watch's role in a Zcash transaction is narrow:

1. **Derive spending keys** from the BIP-39 seed (ZIP-32 for Orchard/Sapling, BIP-44 for transparent)
2. **Sign** transaction hashes (RedPallas for Orchard, RedJubjub for Sapling, ECDSA for transparent)

It does **not** build transactions, compute zk-SNARK proofs, or interact with the
network. Those operations happen on the paired iPhone, which runs the full
`zcash-swift-wallet-sdk` with `std` support.

## Build system: `-Z build-std`

Since watchOS targets are tier-3, there are no pre-built standard library artifacts.
The build script (`build-xcframework.sh`) compiles `core` and `alloc` from source:

```bash
cargo +nightly build \
    -Z build-std=core,alloc \
    --target aarch64-apple-watchos \
    --release
```

This requires a nightly toolchain. Tier-2 targets (iOS, macOS) use standard `cargo build`.

The output is a static library (`libzcash_signer.a`) packaged into an xcframework with
slices for all Apple platforms. The xcframework is consumed by SPM via a `binaryTarget`
in `Package.swift`.

### Build targets

| Platform | Target(s) | Tier | Build method |
|----------|-----------|------|--------------|
| watchOS Device | `aarch64-apple-watchos`, `arm64_32-apple-watchos` | 3 | `build-std=core,alloc` |
| watchOS Simulator | `aarch64-apple-watchos-sim`, `x86_64-apple-watchos-sim` | 3 | `build-std=core,alloc` |
| iOS Device | `aarch64-apple-ios` | 2 | standard |
| iOS Simulator | `aarch64-apple-ios-sim`, `x86_64-apple-ios` | 2 | standard |
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` | 2 | standard (for unit tests) |

## Allocator

`no_std` with `extern crate alloc` requires a global allocator. The crate provides one
in `lib.rs` that delegates to the platform's libc `malloc`/`free`/`realloc`:

```rust
#[cfg(not(feature = "std"))]
mod allocator {
    use core::alloc::{GlobalAlloc, Layout};

    extern "C" {
        fn malloc(size: usize) -> *mut u8;
        fn free(ptr: *mut u8);
        fn realloc(ptr: *mut u8, size: usize) -> *mut u8;
    }

    pub struct LibcAllocator;

    unsafe impl GlobalAlloc for LibcAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 { malloc(layout.size()) }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) { free(ptr) }
        unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
            realloc(ptr, new_size)
        }
    }
}

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOCATOR: allocator::LibcAllocator = allocator::LibcAllocator;
```

**Why libc?** watchOS provides a full C runtime. Using `malloc`/`free` directly is the
simplest approach that works across all four watchOS triples without any platform-specific
Rust support. Alignment is not explicitly passed to `malloc` because the Zcash crypto
types have modest alignment requirements (≤ 8 bytes), and Darwin's `malloc` guarantees
16-byte alignment.

### Alloc error handler

```rust
#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    loop {}
}
```

On allocation failure, the handler enters an infinite loop. In practice, OOM on watchOS
would already be fatal (watchOS aggressively kills background processes well before
exhausting memory). The loop ensures the process does not return from an allocation
failure with undefined state. A future improvement could call `abort()` directly, but
this requires linking against an additional C symbol that may not be available on all
tier-3 targets.

## Panic handler

```rust
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

The panic handler also loops. The `Cargo.toml` sets `panic = "abort"` in the release
profile, which means the compiler eliminates most panic paths at compile time. The
remaining reachable panics (e.g., from `unwrap()` on infallible operations) land here.

**Why not `abort()`?** The `core::intrinsics::abort()` function emits a trap instruction,
which is ideal but requires `#![feature(core_intrinsics)]` and has subtle behavior
differences across targets. The infinite loop is the lowest-common-denominator approach
that satisfies the `-> !` return type. The watchOS runtime will terminate a
non-responsive process after its watchdog timer fires, so the loop is effectively an
abort with a small delay.

The release profile also sets:
- `opt-level = "z"` — optimize for binary size
- `lto = true` — link-time optimization across the full dependency graph
- `codegen-units = 1` — maximize optimization opportunity
- `strip = false` — symbols must be preserved for static library linking

## RNG bridge

Rust's `OsRng` (from the `getrandom` crate) does not support watchOS tier-3 targets.
Instead, the crate receives randomness via a C function pointer callback:

```rust
pub type ZsigRngCallback = unsafe extern "C" fn(*mut u8, usize) -> i32;

pub struct CallbackRng {
    callback: unsafe extern "C" fn(*mut u8, usize) -> i32,
    failed: bool,
}

impl CryptoRng for CallbackRng {}
impl RngCore for CallbackRng { /* delegates to callback */ }
```

The Swift caller passes a callback that wraps `SecRandomCopyBytes`:

```swift
let rngCallback: ZsigRngCallback = { buf, len in
    SecRandomCopyBytes(kSecRandomDefault, len, buf!)
}
```

This gives the Rust code a `CryptoRng + RngCore` implementor backed by the platform's
hardware RNG (Secure Enclave on Apple Watch). The `failed` flag tracks callback errors
so callers can check after a sequence of RNG-consuming operations.

**Why not `register_custom_getrandom!`?** The `getrandom` crate supports custom
implementations via a registration macro, but this interacts poorly with `build-std`
and feature unification across the dependency graph. The callback approach is simpler,
more explicit, and avoids any global state or linker-order dependencies.

## Vendor patches

Two crates are vendored in `vendor/` with patches for watchOS compatibility:

### `blake2b_simd`

The upstream crate enables CPU feature detection (`std::is_x86_feature_detected!`) when
the `std` feature is active. On watchOS Simulator, the CPUID detection hangs
indefinitely. The vendor patch disables the `std` feature by default, falling back to
the portable (non-SIMD) implementation. Performance impact is negligible for the hash
sizes used in ZIP-32 (32–64 bytes).

### `constant_time_eq`

The upstream NEON implementation uses hardcoded `u64` pointer casts. On `arm64_32`
(Apple Watch Series 3), pointers are 32 bits wide, causing the NEON code path to fail.
The vendor patch fixes the pointer arithmetic to work on both `arm64` (64-bit pointers)
and `arm64_32` (32-bit pointers).

Both patches are applied via `[patch.crates-io]` in `Cargo.toml`:

```toml
[patch.crates-io]
constant_time_eq = { path = "vendor/constant_time_eq" }
blake2b_simd = { path = "vendor/blake2b_simd" }
```

## Feature flags

| Feature | `std` required | Description |
|---------|---------------|-------------|
| *(default)* | No | Core key derivation and signing (Orchard, Sapling, transparent) |
| `pczt-signer` | No* | PCZT parsing and full-transaction signing |
| `secure-signer` | No* | SE-encrypted mnemonic decryption + zeroizing key management |
| `debug-tools` | Yes | BIP-39 mnemonic parsing, reference key comparison (host-only) |
| `std` | Yes | Standard library (not available on watchOS) |

\* `pczt-signer` and `secure-signer` enable `rand_core/getrandom` and link against
upstream crates that pull in `std` transitively. This is fine because these features
are only used in the PCZT signing path, which runs on iOS (tier-2) targets where `std`
is available. The base crate (key derivation + low-level signing) remains `no_std`.

The `cfg_attr` at the top of `lib.rs` makes this conditional:

```rust
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
```

## XCFramework build pipeline

The full build pipeline (`build-xcframework.sh`) produces a universal xcframework:

```
Source (Rust)
    │
    ├── cargo +nightly build -Z build-std  (tier-3: watchOS)
    ├── cargo +nightly build               (tier-2: iOS, macOS)
    │
    ▼
Per-target static libraries (.a)
    │
    ├── lipo -create  (merge architectures per platform)
    │
    ▼
Universal static libraries
    │
    ├── xcodebuild -create-xcframework
    │
    ▼
ZcashSigner.xcframework/
    ├── watchos-arm64_arm64_32/
    ├── watchos-arm64_x86_64-simulator/
    ├── ios-arm64/
    ├── ios-arm64_x86_64-simulator/
    └── macos-arm64_x86_64/
```

The wrapper script `tools/rebuild-deps.sh signer` in the main repo handles cache
management and manifest tracking. Development builds (`--dev`) skip the full 9-slice
matrix and build only the slices needed for simulator testing.

## Dependency graph (core, no_std)

```
zcash-signer
├── reddsa 0.5          — RedPallas (Orchard) / RedJubjub (Sapling) signatures
├── pasta_curves 0.5    — Pallas curve (Orchard key math)
├── jubjub 0.10         — Jubjub curve (Sapling key math)
├── ff 0.13             — Finite field traits
├── group 0.13          — Elliptic curve group traits
├── sinsemilla 0.1      — Sinsemilla hash (IVK derivation)
├── blake2b_simd 1.0    — BLAKE2b (ZIP-32 PRF^expand) [vendored]
├── blake2s_simd 1.0    — BLAKE2s (Sapling DiversifyHash)
├── rand_core 0.6       — RNG traits (callback adapter)
├── k256 0.13           — secp256k1 (transparent keys)
├── hmac 0.12           — HMAC-SHA512 (BIP-32 child key derivation)
├── sha2 0.10           — SHA-256 (BIP-32, address hashing)
├── ripemd 0.1          — RIPEMD-160 (P2PKH addresses)
├── aes 0.8             — AES (FF1-AES diversifier derivation)
└── bs58 0.5            — Base58Check (transparent address encoding)
```

All dependencies are configured with `default-features = false` to avoid pulling in `std`.

## Security considerations

- **Key isolation:** Spending keys exist only on the watch. The phone never receives
  private key material — only the signed PCZT.
- **Zeroization:** The `secure-signer` feature wraps seeds and derived keys in
  `Zeroizing<T>` (from the `zeroize` crate), ensuring memory is overwritten on drop.
- **RNG source:** Randomness comes from `SecRandomCopyBytes`, backed by the Secure
  Enclave's hardware RNG. The callback pattern ensures the Rust code never tries to
  access `/dev/urandom` or other OS facilities that may not exist on watchOS.
- **Constant-time operations:** Signature and key operations use the constant-time
  implementations provided by `reddsa`, `k256`, and the vendored `constant_time_eq`.
