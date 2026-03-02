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
