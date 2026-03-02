//! ZcashSigner - Minimal Zcash signing primitives for watchOS
//!
//! This crate provides FFI bindings for:
//! - ZIP-32 Orchard key derivation (spending key, ask)
//! - RedPallas randomized signing for PCZT
//! - BIP-44 transparent address derivation
//! - Orchard address derivation and Unified Address encoding (ZIP-316)
//! - Unified Full Viewing Key (UFVK) derivation and encoding
//!
//! # Architecture
//! - iPhone: Generates zk-SNARK proofs, builds PCZT
//! - Watch: Holds spending keys, performs signing (this crate)

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]

extern crate alloc;

mod address;
mod diversifier;
mod keys;
#[cfg(feature = "pczt-signer")]
pub mod pczt_signer;
#[cfg(feature = "secure-signer")]
mod secure_derive;
#[cfg(feature = "secure-signer")]
mod secure_sign;
mod signing;
mod transparent;

// Re-export for FFI
pub use address::*;
pub use diversifier::*;
pub use keys::*;
pub use signing::*;
pub use transparent::*;

// -----------------------------------------------------------------------------
// Global Allocator (required for no_std + alloc)
// -----------------------------------------------------------------------------

#[cfg(all(not(feature = "std"), not(test)))]
mod allocator {
    use core::alloc::{GlobalAlloc, Layout};

    extern "C" {
        fn malloc(size: usize) -> *mut u8;
        fn free(ptr: *mut u8);
        fn realloc(ptr: *mut u8, size: usize) -> *mut u8;
    }

    pub struct LibcAllocator;

    unsafe impl GlobalAlloc for LibcAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            malloc(layout.size())
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            free(ptr)
        }

        unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
            realloc(ptr, new_size)
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
#[global_allocator]
static ALLOCATOR: allocator::LibcAllocator = allocator::LibcAllocator;

#[cfg(all(not(feature = "std"), not(test)))]
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    loop {}
}

#[cfg(all(not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// -----------------------------------------------------------------------------
// Error Types
// -----------------------------------------------------------------------------

/// Error codes returned by FFI functions
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZsigError {
    /// Operation succeeded
    Success = 0,
    /// Null pointer passed to function
    NullPointer = 1,
    /// Invalid key format or derivation failed
    InvalidKey = 2,
    /// Invalid seed length
    InvalidSeed = 3,
    /// Signing operation failed
    SigningFailed = 4,
    /// Invalid signature format
    InvalidSignature = 5,
    /// Random number generation failed
    RngFailed = 6,
    /// Scalar conversion failed
    ScalarConversionFailed = 7,
    /// Point conversion failed
    PointConversionFailed = 8,
    /// Buffer too small
    BufferTooSmall = 9,
    /// PCZT parse failed
    PcztParseFailed = 10,
    /// PCZT signing failed (Orchard/Sapling/transparent)
    PcztSignFailed = 11,
    /// PCZT invalid key for signing
    PcztInvalidKey = 12,
    /// Seed derivation failed (secure signer)
    SeedDerivationFailed = 13,
}

// -----------------------------------------------------------------------------
// RNG Adapter
// -----------------------------------------------------------------------------

use rand_core::{CryptoRng, RngCore};

/// RNG adapter that reads from a callback provided by Swift
pub struct CallbackRng {
    callback: unsafe extern "C" fn(*mut u8, usize) -> i32,
    failed: bool,
}

impl CallbackRng {
    pub fn new(callback: unsafe extern "C" fn(*mut u8, usize) -> i32) -> Self {
        Self {
            callback,
            failed: false,
        }
    }

    pub fn has_failed(&self) -> bool {
        self.failed
    }
}

impl RngCore for CallbackRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let result = unsafe { (self.callback)(dest.as_mut_ptr(), dest.len()) };
        if result != 0 {
            self.failed = true;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let result = unsafe { (self.callback)(dest.as_mut_ptr(), dest.len()) };
        if result == 0 {
            Ok(())
        } else {
            self.failed = true;
            Err(rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
        }
    }
}

impl CryptoRng for CallbackRng {}

// -----------------------------------------------------------------------------
// FFI Types
// -----------------------------------------------------------------------------

/// RNG callback type - must fill buffer with cryptographically secure random bytes
pub type ZsigRngCallback = unsafe extern "C" fn(*mut u8, usize) -> i32;

/// Orchard spending key (32 bytes)
#[repr(C)]
pub struct ZsigOrchardSpendingKey {
    pub bytes: [u8; 32],
}

/// Orchard spend authorization key "ask" (32-byte scalar on Pallas)
#[repr(C)]
pub struct ZsigOrchardAsk {
    pub bytes: [u8; 32],
}

/// RedPallas signature (64 bytes: R + S)
#[repr(C)]
pub struct ZsigOrchardSignature {
    pub bytes: [u8; 64],
}

/// Sapling spending key (32 bytes)
#[repr(C)]
pub struct ZsigSaplingSpendingKey {
    pub bytes: [u8; 32],
}

/// Sapling spend authorization key "ask" (32-byte scalar on Jubjub)
#[repr(C)]
pub struct ZsigSaplingAsk {
    pub bytes: [u8; 32],
}

/// RedJubjub signature (64 bytes: R + S)
#[repr(C)]
pub struct ZsigSaplingSignature {
    pub bytes: [u8; 64],
}

// -----------------------------------------------------------------------------
// Version Info
// -----------------------------------------------------------------------------

static VERSION: &[u8] = b"0.1.0\0";

/// Get the library version string
#[no_mangle]
pub extern "C" fn zsig_version() -> *const u8 {
    VERSION.as_ptr()
}

// -----------------------------------------------------------------------------
// FFI Function Re-exports (implemented in submodules)
// -----------------------------------------------------------------------------

// The actual FFI functions are implemented in keys.rs, signing.rs, and transparent.rs
// and are exported via #[no_mangle] pub extern "C"

// -----------------------------------------------------------------------------
// Memory Management
// -----------------------------------------------------------------------------

/// Free a heap-allocated buffer returned by `zsig_pczt_sign_secure`.
///
/// # Safety
/// - `ptr` must have been returned by `zsig_pczt_sign_secure`
/// - `len` must be the length that was written to `out_len`
/// - Must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn zsig_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = alloc::boxed::Box::from_raw(core::slice::from_raw_parts_mut(ptr, len));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::num::NonZeroU32;
    use core::ptr;
    use ff::PrimeField;
    use pasta_curves::pallas::Scalar as PallasScalar;
    use reddsa::orchard::SpendAuth as OrchardSpendAuth;
    use std::sync::{Mutex, OnceLock};
    use std::vec::Vec;

    #[derive(Clone, Default)]
    struct CallbackState {
        bytes: Vec<u8>,
        offset: usize,
        call_count: usize,
        fail_on_call: Option<usize>,
        requested_lengths: Vec<usize>,
    }

    static CALLBACK_STATE: OnceLock<Mutex<CallbackState>> = OnceLock::new();
    static TEST_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

    fn callback_state() -> &'static Mutex<CallbackState> {
        CALLBACK_STATE.get_or_init(|| Mutex::new(CallbackState::default()))
    }

    fn test_guard() -> &'static Mutex<()> {
        TEST_GUARD.get_or_init(|| Mutex::new(()))
    }

    fn install_callback_state(bytes: Vec<u8>, fail_on_call: Option<usize>) {
        let mut state = callback_state()
            .lock()
            .expect("callback test state mutex poisoned");
        *state = CallbackState {
            bytes,
            offset: 0,
            call_count: 0,
            fail_on_call,
            requested_lengths: Vec::new(),
        };
    }

    fn snapshot_callback_state() -> CallbackState {
        callback_state()
            .lock()
            .expect("callback test state mutex poisoned")
            .clone()
    }

    unsafe extern "C" fn deterministic_callback(buffer: *mut u8, length: usize) -> i32 {
        let mut state = callback_state()
            .lock()
            .expect("callback test state mutex poisoned");
        state.call_count += 1;
        state.requested_lengths.push(length);

        if let Some(fail_on_call) = state.fail_on_call {
            if state.call_count >= fail_on_call {
                return -1;
            }
        }

        if state.offset + length > state.bytes.len() {
            return -2;
        }

        if length > 0 {
            let src = &state.bytes[state.offset..state.offset + length];
            ptr::copy_nonoverlapping(src.as_ptr(), buffer, length);
        }
        state.offset += length;
        0
    }

    struct DeterministicRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl DeterministicRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }

        fn consumed(&self) -> usize {
            self.offset
        }
    }

    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }

        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            let end = self.offset + dest.len();
            if end > self.bytes.len() {
                return Err(rand_core::Error::from(NonZeroU32::new(2).unwrap()));
            }
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(())
        }
    }

    impl CryptoRng for DeterministicRng {}

    fn canonical_ask(value: u64) -> [u8; 32] {
        PallasScalar::from(value).to_repr().into()
    }

    fn deterministic_stream(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (((index * 37) + 11) & 0xff) as u8)
            .collect()
    }

    #[test]
    fn callback_rng_preserves_byte_order_and_requested_length() {
        let _guard = test_guard().lock().expect("test guard mutex poisoned");
        let stream = deterministic_stream(128);
        install_callback_state(stream.clone(), None);

        let mut rng = CallbackRng::new(deterministic_callback);
        let mut out = [0u8; 37];
        rng.fill_bytes(&mut out);

        assert_eq!(out.as_slice(), &stream[..37]);
        assert!(!rng.has_failed());

        let state = snapshot_callback_state();
        assert_eq!(state.call_count, 1);
        assert_eq!(state.requested_lengths.as_slice(), &[37]);
        assert_eq!(state.offset, 37);
    }

    #[test]
    fn callback_rng_failure_sets_flag_and_returns_error() {
        let _guard = test_guard().lock().expect("test guard mutex poisoned");
        install_callback_state(deterministic_stream(64), Some(1));

        let mut rng = CallbackRng::new(deterministic_callback);
        let mut out = [0u8; 16];

        assert!(rng.try_fill_bytes(&mut out).is_err());
        assert!(rng.has_failed());

        let state = snapshot_callback_state();
        assert_eq!(state.call_count, 1);
        assert_eq!(state.requested_lengths.as_slice(), &[16]);
    }

    #[test]
    fn orchard_signature_matches_callback_rng_cross_check_vector() {
        const KNOWN_GOOD_SIGNATURE_HEX: &str =
            "39ac9bc738af5c0701edbeed4d64af9dc73ec20d973546166776bec993535212\
             270de742c06f8023c1c25d0f2bab1cf1ed47a054b653e128e8feac17acc43308";

        let _guard = test_guard().lock().expect("test guard mutex poisoned");
        let ask_bytes = canonical_ask(42);
        let ask = ZsigOrchardAsk { bytes: ask_bytes };
        let message = b"callback-rng-cross-check-vector";
        let stream = deterministic_stream(512);
        install_callback_state(stream.clone(), None);

        let mut signature_out = ZsigOrchardSignature { bytes: [0u8; 64] };
        let ffi_result = unsafe {
            zsig_sign_orchard(
                &ask,
                message.as_ptr(),
                message.len(),
                &mut signature_out,
                deterministic_callback,
            )
        };
        assert_eq!(ffi_result, ZsigError::Success);

        let signing_key: reddsa::SigningKey<OrchardSpendAuth> =
            reddsa::SigningKey::try_from(ask_bytes).expect("canonical ask must create signing key");
        let mut deterministic_rng = DeterministicRng::new(stream);
        let expected_sig: reddsa::Signature<OrchardSpendAuth> =
            signing_key.sign(&mut deterministic_rng, message);
        let expected_bytes: [u8; 64] = expected_sig.into();

        assert_eq!(signature_out.bytes, expected_bytes);
        assert_eq!(hex::encode(signature_out.bytes), KNOWN_GOOD_SIGNATURE_HEX);

        let state = snapshot_callback_state();
        assert_eq!(state.offset, deterministic_rng.consumed());
    }

    #[test]
    fn orchard_sign_returns_rng_failed_when_callback_errors() {
        let _guard = test_guard().lock().expect("test guard mutex poisoned");
        let ask = ZsigOrchardAsk {
            bytes: canonical_ask(7),
        };
        let message = [0xAB; 32];
        let mut signature_out = ZsigOrchardSignature { bytes: [0u8; 64] };

        install_callback_state(deterministic_stream(64), Some(1));

        let result = unsafe {
            zsig_sign_orchard(
                &ask,
                message.as_ptr(),
                message.len(),
                &mut signature_out,
                deterministic_callback,
            )
        };

        assert_eq!(result, ZsigError::RngFailed);
    }
}
