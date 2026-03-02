// secp256k1_stubs.c
//
// Weak stub implementations of secp256k1 C callback symbols referenced by
// libzcash_signer.a. When the real libzcashlc is linked (phone target), its
// strong definitions win. On the watch (no libzcashlc), these no-op stubs
// satisfy the linker.

void __attribute__((weak)) rustsecp256k1_v0_10_0_default_error_callback_fn(const char *msg, void *data) {
    (void)msg; (void)data;
}

void __attribute__((weak)) rustsecp256k1_v0_10_0_default_illegal_callback_fn(const char *msg, void *data) {
    (void)msg; (void)data;
}
