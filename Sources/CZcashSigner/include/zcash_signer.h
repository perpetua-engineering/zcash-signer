/*
 * ZcashSigner - Minimal Zcash signing primitives for watchOS
 *
 * This header provides the C FFI for:
 * - ZIP-32 Orchard key derivation (spending key, ask)
 * - RedPallas randomized signing for PCZT
 * - BIP-44 transparent address derivation
 *
 * Architecture:
 * - iPhone: Generates zk-SNARK proofs, builds PCZT
 * - Watch: Holds spending keys, performs signing (this library)
 */

#ifndef ZCASH_SIGNER_H
#define ZCASH_SIGNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

typedef enum {
    ZSIG_SUCCESS = 0,
    ZSIG_ERROR_NULL_POINTER = 1,
    ZSIG_ERROR_INVALID_KEY = 2,
    ZSIG_ERROR_INVALID_SEED = 3,
    ZSIG_ERROR_SIGNING_FAILED = 4,
    ZSIG_ERROR_INVALID_SIGNATURE = 5,
    ZSIG_ERROR_RNG_FAILED = 6,
    ZSIG_ERROR_SCALAR_CONVERSION_FAILED = 7,
    ZSIG_ERROR_POINT_CONVERSION_FAILED = 8,
    ZSIG_ERROR_BUFFER_TOO_SMALL = 9,
} ZsigError;

/* ============================================================================
 * Key Types
 * ============================================================================ */

/*
 * Orchard spending key (32 bytes)
 * Derived via ZIP-32 path: m/32'/coin_type'/account'
 */
typedef struct {
    uint8_t bytes[32];
} ZsigOrchardSpendingKey;

/*
 * Orchard spend authorization key "ask" (32-byte scalar on Pallas)
 * Derived from spending key: ask = PRF^expand(sk, 0x06)
 */
typedef struct {
    uint8_t bytes[32];
} ZsigOrchardAsk;

/*
 * RedPallas signature (64 bytes: R + S components)
 * Used for Orchard spend authorization
 */
typedef struct {
    uint8_t bytes[64];
} ZsigOrchardSignature;

/* ============================================================================
 * RNG Callback
 * ============================================================================ */

/*
 * RNG callback type - must fill buffer with cryptographically secure random bytes
 * On Apple platforms, use SecRandomCopyBytes
 *
 * Parameters:
 *   buffer: Pointer to buffer to fill
 *   length: Number of bytes to generate
 *
 * Returns:
 *   0 on success, non-zero on failure
 */
typedef int32_t (*ZsigRngCallback)(uint8_t* buffer, size_t length);

/* ============================================================================
 * ZIP-32 Key Derivation
 * ============================================================================ */

/*
 * Zcash mainnet coin type (BIP-44 / ZIP-32)
 */
#define ZSIG_MAINNET_COIN_TYPE 133

/*
 * Derive an Orchard spending key from a BIP-39 seed using ZIP-32
 *
 * Path: m/32'/coin_type'/account'
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes (typically 64 bytes)
 *   seed_len: Length of the seed (must be 32-252 bytes per ZIP-32)
 *   coin_type: Coin type for derivation (use ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index (typically 0)
 *   key_out: Pointer to receive the derived spending key (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_spending_key(const uint8_t* seed,
                                            size_t seed_len,
                                            uint32_t coin_type,
                                            uint32_t account,
                                            ZsigOrchardSpendingKey* key_out);

/*
 * Derive the spend authorization key (ask) from a spending key
 *
 * ask = PRF^expand(sk, 0x06) reduced to a Pallas scalar
 *
 * Parameters:
 *   spending_key: Pointer to the spending key (must not be NULL)
 *   ask_out: Pointer to receive the ask (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_ask(const ZsigOrchardSpendingKey* spending_key,
                                   ZsigOrchardAsk* ask_out);

/*
 * Convenience function: derive ask directly from seed
 *
 * Combines zsig_derive_orchard_spending_key and zsig_derive_orchard_ask.
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes (typically 64 bytes)
 *   seed_len: Length of the seed (must be 32-252 bytes per ZIP-32)
 *   coin_type: Coin type for derivation (use ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index (typically 0)
 *   ask_out: Pointer to receive the ask (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_ask_from_seed(const uint8_t* seed,
                                             size_t seed_len,
                                             uint32_t coin_type,
                                             uint32_t account,
                                             ZsigOrchardAsk* ask_out);

/* ============================================================================
 * RedPallas Signing
 * ============================================================================ */

/*
 * Sign using RedPallas with randomized key (main PCZT signing function)
 *
 * For PCZT signing, each Orchard spend has an alpha randomizer.
 * The signature verifies against rk = ak + [alpha]G, so we sign with
 * the randomized key: ask_randomized = ask + alpha.
 *
 * Parameters:
 *   ask: Pointer to the spend authorization key (must not be NULL)
 *   alpha: Pointer to 32-byte alpha randomizer from PCZT (must not be NULL)
 *   sighash: Pointer to 32-byte transaction sighash (must not be NULL)
 *   signature_out: Pointer to receive the signature (must not be NULL)
 *   rng: Callback function for random number generation
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_sign_orchard_randomized(const ZsigOrchardAsk* ask,
                                        const uint8_t* alpha,
                                        const uint8_t* sighash,
                                        ZsigOrchardSignature* signature_out,
                                        ZsigRngCallback rng);

/*
 * Sign using RedPallas (non-randomized, for testing)
 *
 * Parameters:
 *   ask: Pointer to the spend authorization key (must not be NULL)
 *   message: Pointer to the message data (must not be NULL)
 *   message_len: Length of the message in bytes
 *   signature_out: Pointer to receive the signature (must not be NULL)
 *   rng: Callback function for random number generation
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_sign_orchard(const ZsigOrchardAsk* ask,
                             const uint8_t* message,
                             size_t message_len,
                             ZsigOrchardSignature* signature_out,
                             ZsigRngCallback rng);

/*
 * Verify a RedPallas signature (for testing)
 *
 * Parameters:
 *   ak: Pointer to 32-byte authorization key (verification key)
 *   message: Pointer to the message data (must not be NULL)
 *   message_len: Length of the message in bytes
 *   signature: Pointer to the signature (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS if signature is valid, error code otherwise
 */
ZsigError zsig_verify_orchard(const uint8_t* ak,
                               const uint8_t* message,
                               size_t message_len,
                               const ZsigOrchardSignature* signature);

/*
 * Derive ak (authorization key) from ask
 *
 * ak = ask * G where G is the Orchard SpendAuth basepoint
 *
 * Parameters:
 *   ask: Pointer to the spend authorization key (must not be NULL)
 *   ak_out: Pointer to 32-byte buffer for ak output (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_ak_from_ask(const ZsigOrchardAsk* ask,
                                   uint8_t* ak_out);

/* ============================================================================
 * BIP-44 Transparent Address Derivation
 * ============================================================================ */

/*
 * Derive a transparent P2PKH address from seed using BIP-44
 *
 * Path: m/44'/133'/account'/0/index
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes (typically 64 bytes)
 *   seed_len: Length of the seed (16-64 bytes)
 *   account: Account index (typically 0)
 *   index: Address index (0 for first address)
 *   mainnet: true for mainnet (t1...), false for testnet (tm...)
 *   output: Buffer for the null-terminated address string (at least 36 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of address string (excluding null terminator), or 0 on error
 */
size_t zsig_derive_transparent_address(const uint8_t* seed,
                                        size_t seed_len,
                                        uint32_t account,
                                        uint32_t index,
                                        bool mainnet,
                                        uint8_t* output,
                                        size_t output_len);

/*
 * Derive transparent pubkey hash (20 bytes) from seed
 *
 * This is useful for creating Unified Addresses with a transparent receiver.
 * The hash is RIPEMD160(SHA256(compressed_pubkey)).
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes (typically 64 bytes)
 *   seed_len: Length of the seed (16-64 bytes)
 *   account: Account index (typically 0)
 *   index: Address index (0 for first address)
 *   hash_out: Buffer for 20-byte pubkey hash output
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_transparent_pubkey_hash(const uint8_t* seed,
                                               size_t seed_len,
                                               uint32_t account,
                                               uint32_t index,
                                               uint8_t* hash_out);

/* ============================================================================
 * Version Info
 * ============================================================================ */

/*
 * Get the library version string
 * Returns a null-terminated C string
 */
const char* zsig_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCASH_SIGNER_H */
