// WalletCoreStubs.c
//
// Stub implementations of WalletCore C FFI symbols referenced by the
// secure-signer feature in libzcash_signer.a.  These functions are only
// called on the watch (SE-encrypted mnemonic path) and are never reached
// by the pczt-cli, but the linker needs them resolved.  Every stub
// returns NULL / 0 so any accidental call fails safely.

#include <stddef.h>
#include <stdint.h>

void *TWDataCreateWithBytes(const uint8_t *bytes, size_t size) { (void)bytes; (void)size; return NULL; }
const uint8_t *TWDataBytes(const void *data) { (void)data; return NULL; }
size_t TWDataSize(const void *data) { (void)data; return 0; }
void TWDataDelete(void *data) { (void)data; }
void *TWStringCreateWithUTF8Bytes(const char *str) { (void)str; return NULL; }
void TWStringDelete(void *str) { (void)str; }
void *TWSecureSignerDeriveSeed(const void *mnemonic, const void *key_ref, const void *salt) { (void)mnemonic; (void)key_ref; (void)salt; return NULL; }
void TWSecureSignerFreeSeed(void *seed) { (void)seed; }

// secp256k1 C FFI callback stubs. Weak so libzcashlc's real definitions win
// when both are linked (test target). Only used when libzcashlc is absent.
__attribute__((weak)) void rustsecp256k1_v0_10_0_default_error_callback_fn(const char *msg, void *data) { (void)msg; (void)data; }
__attribute__((weak)) void rustsecp256k1_v0_10_0_default_illegal_callback_fn(const char *msg, void *data) { (void)msg; (void)data; }
