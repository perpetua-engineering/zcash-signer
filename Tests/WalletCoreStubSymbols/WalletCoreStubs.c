#include <stddef.h>
#include <stdint.h>

typedef const void TWData;
typedef const void TWString;

TWData *TWDataCreateWithBytes(const uint8_t *bytes, size_t size) {
    (void)bytes;
    (void)size;
    return NULL;
}

uint8_t *TWDataBytes(TWData *data) {
    (void)data;
    return NULL;
}

size_t TWDataSize(TWData *data) {
    (void)data;
    return 0;
}

void TWDataDelete(TWData *data) {
    (void)data;
}

TWString *TWStringCreateWithUTF8Bytes(const char *bytes) {
    (void)bytes;
    return NULL;
}

void TWStringDelete(TWString *string) {
    (void)string;
}

TWData *TWSecureSignerDeriveSeed(
    TWData *encryptedMnemonic,
    const void *seKeyRef,
    TWString *hkdfSalt
) {
    (void)encryptedMnemonic;
    (void)seKeyRef;
    (void)hkdfSalt;
    return NULL;
}

void TWSecureSignerFreeSeed(TWData *seed) {
    (void)seed;
}

/* secp256k1 C FFI callback stubs.
   libzcash_signer.a's secp256k1 C source references these as undefined
   symbols. In the real app they're provided by the secp256k1_sys Rust
   object, but nmedit localises those definitions to avoid duplicate-symbol
   errors with libzcashlc. Provide fallback definitions here. */

/* Weak so libzcashlc's real definitions win when both are linked. */
__attribute__((weak))
void rustsecp256k1_v0_10_0_default_error_callback_fn(
    const char *msg, void *data) {
    (void)msg;
    (void)data;
}

__attribute__((weak))
void rustsecp256k1_v0_10_0_default_illegal_callback_fn(
    const char *msg, void *data) {
    (void)msg;
    (void)data;
}
