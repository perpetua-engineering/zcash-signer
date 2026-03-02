// Secp256k1Stubs.c
//
// Weak stub implementations of the secp256k1 C FFI callback symbols
// referenced by libzcash_signer.a when built with pczt-signer feature.
// Weak so that real implementations (e.g. from libzcashlc) win when present.

#include <stddef.h>

__attribute__((weak)) void rustsecp256k1_v0_10_0_default_error_callback_fn(const char *msg, void *data) { (void)msg; (void)data; }
__attribute__((weak)) void rustsecp256k1_v0_10_0_default_illegal_callback_fn(const char *msg, void *data) { (void)msg; (void)data; }
