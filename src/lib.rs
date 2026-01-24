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
mod keys;
mod signing;
mod transparent;

// Re-export for FFI
pub use address::*;
pub use keys::*;
pub use signing::*;
pub use transparent::*;

// -----------------------------------------------------------------------------
// Global Allocator (required for no_std + alloc)
// -----------------------------------------------------------------------------

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

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOCATOR: allocator::LibcAllocator = allocator::LibcAllocator;

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    loop {}
}

#[cfg(not(feature = "std"))]
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
