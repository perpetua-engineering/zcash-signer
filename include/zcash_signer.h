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
    ZSIG_ERROR_PCZT_PARSE_FAILED = 10,
    ZSIG_ERROR_PCZT_SIGN_FAILED = 11,
    ZSIG_ERROR_PCZT_INVALID_KEY = 12,
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

/*
 * Sapling spending key (32 bytes)
 * Derived via ZIP-32 path: m/32'/coin_type'/account'
 */
typedef struct {
    uint8_t bytes[32];
} ZsigSaplingSpendingKey;

/*
 * Sapling spend authorization key "ask" (32-byte scalar on Jubjub)
 * Derived from spending key: ask = PRF^expand(sk, 0x00)
 */
typedef struct {
    uint8_t bytes[32];
} ZsigSaplingAsk;

/*
 * RedJubjub signature (64 bytes: R + S components)
 * Used for Sapling spend authorization
 */
typedef struct {
    uint8_t bytes[64];
} ZsigSaplingSignature;

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
 * ZIP-32 Sapling Key Derivation
 * ============================================================================ */

/*
 * Derive a Sapling spending key from a BIP-39 seed using ZIP-32
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
ZsigError zsig_derive_sapling_spending_key(const uint8_t* seed,
                                            size_t seed_len,
                                            uint32_t coin_type,
                                            uint32_t account,
                                            ZsigSaplingSpendingKey* key_out);

/*
 * Derive the Sapling spend authorization key (ask) from a spending key
 *
 * ask = PRF^expand(sk, 0x00) reduced to a Jubjub scalar
 *
 * Parameters:
 *   spending_key: Pointer to the spending key (must not be NULL)
 *   ask_out: Pointer to receive the ask (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_sapling_ask(const ZsigSaplingSpendingKey* spending_key,
                                   ZsigSaplingAsk* ask_out);

/*
 * Convenience function: derive Sapling ask directly from seed
 *
 * Combines zsig_derive_sapling_spending_key and zsig_derive_sapling_ask.
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
ZsigError zsig_derive_sapling_ask_from_seed(const uint8_t* seed,
                                             size_t seed_len,
                                             uint32_t coin_type,
                                             uint32_t account,
                                             ZsigSaplingAsk* ask_out);

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
 * RedJubjub Signing (Sapling)
 * ============================================================================ */

/*
 * Sign using RedJubjub with randomized key (main PCZT Sapling signing function)
 *
 * For PCZT signing, each Sapling spend has an alpha randomizer.
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
ZsigError zsig_sign_sapling_randomized(const ZsigSaplingAsk* ask,
                                        const uint8_t* alpha,
                                        const uint8_t* sighash,
                                        ZsigSaplingSignature* signature_out,
                                        ZsigRngCallback rng);

/*
 * Sign using RedJubjub (non-randomized, for testing)
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
ZsigError zsig_sign_sapling(const ZsigSaplingAsk* ask,
                             const uint8_t* message,
                             size_t message_len,
                             ZsigSaplingSignature* signature_out,
                             ZsigRngCallback rng);

/*
 * Verify a RedJubjub signature (for testing)
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
ZsigError zsig_verify_sapling(const uint8_t* ak,
                               const uint8_t* message,
                               size_t message_len,
                               const ZsigSaplingSignature* signature);

/*
 * Derive Sapling ak (authorization key) from ask
 *
 * ak = ask * G where G is the Sapling SpendAuth basepoint
 *
 * Parameters:
 *   ask: Pointer to the spend authorization key (must not be NULL)
 *   ak_out: Pointer to 32-byte buffer for ak output (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_sapling_ak_from_ask(const ZsigSaplingAsk* ask,
                                           uint8_t* ak_out);

/* ============================================================================
 * FF1-AES256 Diversifier Derivation (ZIP-32)
 * ============================================================================ */

/*
 * Derive the first valid Sapling diversifier index from a BIP-39 seed
 *
 * This function derives the Sapling diversifier key (dk) from the seed,
 * then searches for the first index where the diversifier produces a valid
 * Sapling address (DiversifyHash doesn't return bottom).
 *
 * The returned index should be used for:
 * - Sapling address derivation (diversifier index)
 * - Transparent address derivation (BIP-44 index)
 *
 * This ensures the Unified Address will have matching diversifier indices
 * across all receiver types, as required by ZIP-316.
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed (32-252 bytes per ZIP-32)
 *   coin_type: Coin type for derivation (use ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   index_out: Pointer to receive the first valid diversifier index (must not be NULL)
 *   diversifier_out: Optional pointer to receive 11-byte diversifier (can be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_first_valid_diversifier_index(const uint8_t* seed,
                                                      size_t seed_len,
                                                      uint32_t coin_type,
                                                      uint32_t account,
                                                      uint64_t* index_out,
                                                      uint8_t* diversifier_out);

/*
 * Derive diversifier from diversifier key and index using FF1-AES256
 *
 * Parameters:
 *   dk: 32-byte diversifier key
 *   index: Diversifier index
 *   diversifier_out: Buffer for 11-byte diversifier output
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_diversifier(const uint8_t* dk,
                                   uint64_t index,
                                   uint8_t* diversifier_out);

/*
 * Find the first valid diversifier index for a given diversifier key
 *
 * Parameters:
 *   dk: 32-byte diversifier key
 *   index_out: Pointer to receive first valid index
 *   diversifier_out: Buffer for 11-byte diversifier output
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_find_valid_diversifier(const uint8_t* dk,
                                       uint64_t* index_out,
                                       uint8_t* diversifier_out);

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
 * Transparent Signing
 * ============================================================================ */

/*
 * Sign a transparent input sighash using BIP-44 derived key
 *
 * Parameters:
 *   seed: BIP-39 seed bytes
 *   seed_len: Length of seed (usually 64)
 *   derivation_path: BIP-32 derivation path components with hardened bits
 *   path_len: Number of path components (usually 5, max 10)
 *   sighash: 32-byte sighash to sign
 *   sighash_type: Sighash type (usually 0x01 for SIGHASH_ALL)
 *   signature_out: Output buffer for DER signature
 *   signature_out_len: Size of signature output buffer (must be >= 72)
 *   signature_len_out: Output for actual signature length written
 *   pubkey_out: Output buffer for compressed pubkey (33 bytes)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 *   ZSIG_ERROR_BUFFER_TOO_SMALL if signature_out_len < 72
 *   ZSIG_ERROR_INVALID_KEY if path_len is 0 or > 10
 */
ZsigError zsig_sign_transparent(const uint8_t* seed,
                                 size_t seed_len,
                                 const uint32_t* derivation_path,
                                 size_t path_len,
                                 const uint8_t* sighash,
                                 uint8_t sighash_type,
                                 uint8_t* signature_out,
                                 size_t signature_out_len,
                                 size_t* signature_len_out,
                                 uint8_t* pubkey_out);

/* ============================================================================
 * Orchard Address Types
 * ============================================================================ */

/*
 * Orchard payment address (diversifier + pk_d)
 */
typedef struct {
    uint8_t diversifier[11];
    uint8_t pk_d[32];
} ZsigOrchardAddress;

/*
 * Orchard Full Viewing Key components
 */
typedef struct {
    uint8_t ak[32];   /* authorization key */
    uint8_t nk[32];   /* nullifier deriving key */
    uint8_t rivk[32]; /* randomized ivk */
} ZsigOrchardFullViewingKey;

/* Sapling Full Viewing Key components
 * ZIP-316 format: ak (32) + nk (32) + ovk (32) + dk (32) = 128 bytes
 */
typedef struct {
    uint8_t ak[32];   /* authorization key */
    uint8_t nk[32];   /* nullifier deriving key */
    uint8_t ovk[32];  /* outgoing viewing key */
    uint8_t dk[32];   /* diversifier key */
} ZsigSaplingFullViewingKey;

/* ============================================================================
 * Orchard Address Derivation (ZIP-316)
 * ============================================================================ */

/*
 * Derive Orchard address from spending key
 *
 * Parameters:
 *   spending_key: Pointer to 32-byte spending key
 *   address_out: Pointer to receive the address
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_address(const uint8_t* spending_key,
                                       ZsigOrchardAddress* address_out);

/*
 * Derive Orchard address from seed using ZIP-32
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   address_out: Pointer to receive the address
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_address_from_seed(const uint8_t* seed,
                                                 size_t seed_len,
                                                 uint32_t coin_type,
                                                 uint32_t account,
                                                 ZsigOrchardAddress* address_out);

/* ============================================================================
 * Unified Address Encoding (ZIP-316)
 * ============================================================================ */

/*
 * Encode an Orchard address as a Unified Address string
 *
 * Parameters:
 *   address: Pointer to the Orchard address
 *   mainnet: true for mainnet (u...), false for testnet (utest...)
 *   output: Buffer for null-terminated UA string (at least 256 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UA string (excluding null terminator), or 0 on error
 */
size_t zsig_encode_unified_address(const ZsigOrchardAddress* address,
                                    bool mainnet,
                                    uint8_t* output,
                                    size_t output_len);

/*
 * Encode a Unified Address with both Orchard and transparent receivers
 *
 * Creates a UA that CEXs can use - they'll send to the transparent receiver
 * if they don't support Orchard.
 *
 * Parameters:
 *   orchard_addr: Pointer to the Orchard address
 *   transparent_pkh: Pointer to 20-byte transparent pubkey hash
 *   mainnet: true for mainnet, false for testnet
 *   output: Buffer for null-terminated UA string (at least 256 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UA string (excluding null terminator), or 0 on error
 */
size_t zsig_encode_unified_address_with_transparent(const ZsigOrchardAddress* orchard_addr,
                                                     const uint8_t* transparent_pkh,
                                                     bool mainnet,
                                                     uint8_t* output,
                                                     size_t output_len);

/* ============================================================================
 * Full Viewing Key Derivation (ZIP-316)
 * ============================================================================ */

/*
 * Derive Orchard Full Viewing Key from seed
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   fvk_out: Pointer to receive the FVK
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_orchard_full_viewing_key(const uint8_t* seed,
                                                size_t seed_len,
                                                uint32_t coin_type,
                                                uint32_t account,
                                                ZsigOrchardFullViewingKey* fvk_out);

/*
 * Derive Sapling Full Viewing Key from seed
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   fvk_out: Pointer to receive the FVK
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code on failure
 */
ZsigError zsig_derive_sapling_full_viewing_key(const uint8_t* seed,
                                                size_t seed_len,
                                                uint32_t coin_type,
                                                uint32_t account,
                                                ZsigSaplingFullViewingKey* fvk_out);

/*
 * Encode an Orchard FVK as a Unified Full Viewing Key string
 *
 * Parameters:
 *   fvk: Pointer to the Orchard FVK
 *   mainnet: true for mainnet (uview...), false for testnet (uviewtest...)
 *   output: Buffer for null-terminated UFVK string (at least 512 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UFVK string (excluding null terminator), or 0 on error
 */
size_t zsig_encode_unified_full_viewing_key(const ZsigOrchardFullViewingKey* fvk,
                                             bool mainnet,
                                             uint8_t* output,
                                             size_t output_len);

/*
 * Derive UFVK string directly from seed (convenience function)
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   mainnet: true for mainnet, false for testnet
 *   output: Buffer for null-terminated UFVK string (at least 512 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UFVK string (positive), or negative error code on failure
 */
int32_t zsig_derive_ufvk_string(const uint8_t* seed,
                                 size_t seed_len,
                                 uint32_t coin_type,
                                 uint32_t account,
                                 bool mainnet,
                                 uint8_t* output,
                                 size_t output_len);

/* ============================================================================
 * Combined UFVK (Transparent + Sapling + Orchard)
 * ============================================================================ */

/* Transparent Full Viewing Key (for combined UFVK)
 * ZIP-316 format: chain_code (32) + compressed pubkey (33) = 65 bytes
 */
typedef struct {
    uint8_t chain_code[32];
    uint8_t pubkey[33];
} ZsigTransparentFullViewingKey;

/* Combined Full Viewing Key (Transparent + Sapling + Orchard) */
typedef struct {
    ZsigTransparentFullViewingKey transparent;
    ZsigSaplingFullViewingKey sapling;
    ZsigOrchardFullViewingKey orchard;
} ZsigCombinedFullViewingKey;

/*
 * Derive transparent Full Viewing Key from seed using BIP-44
 * Path: m/44'/133'/account'
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed (typically 64)
 *   account: Account index
 *   fvk_out: Output FVK (chain_code + compressed pubkey)
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code otherwise
 */
ZsigError zsig_derive_transparent_full_viewing_key(const uint8_t* seed,
                                                    size_t seed_len,
                                                    uint32_t account,
                                                    ZsigTransparentFullViewingKey* fvk_out);

/*
 * Derive combined Full Viewing Key (Transparent + Sapling + Orchard) from seed
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   fvk_out: Output combined FVK
 *
 * Returns:
 *   ZSIG_SUCCESS on success, error code otherwise
 */
ZsigError zsig_derive_combined_full_viewing_key(const uint8_t* seed,
                                                 size_t seed_len,
                                                 uint32_t coin_type,
                                                 uint32_t account,
                                                 ZsigCombinedFullViewingKey* fvk_out);

/*
 * Encode a Combined Full Viewing Key as a Unified Full Viewing Key string
 *
 * Creates a UFVK with transparent (P2PKH), Sapling, and Orchard receivers.
 * Per ZIP-316, receivers are ordered by typecode ascending.
 *
 * Parameters:
 *   fvk: The combined FVK to encode
 *   mainnet: true for mainnet (uview...), false for testnet (uviewtest...)
 *   output: Buffer for null-terminated UFVK string (at least 512 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UFVK string (excluding null terminator), or 0 on error
 */
size_t zsig_encode_combined_full_viewing_key(const ZsigCombinedFullViewingKey* fvk,
                                              bool mainnet,
                                              uint8_t* output,
                                              size_t output_len);

/*
 * Derive Combined UFVK string directly from seed (convenience function)
 *
 * Parameters:
 *   seed: The BIP-39 seed bytes
 *   seed_len: Length of the seed
 *   coin_type: Coin type (ZSIG_MAINNET_COIN_TYPE = 133)
 *   account: Account index
 *   mainnet: true for mainnet, false for testnet
 *   output: Buffer for null-terminated UFVK string (at least 512 bytes)
 *   output_len: Size of output buffer
 *
 * Returns:
 *   Length of UFVK string (positive), or negative error code on failure
 */
int32_t zsig_derive_combined_ufvk_string(const uint8_t* seed,
                                          size_t seed_len,
                                          uint32_t coin_type,
                                          uint32_t account,
                                          bool mainnet,
                                          uint8_t* output,
                                          size_t output_len);

/* ============================================================================
 * PCZT Signing (Partially Created Zcash Transaction)
 * ============================================================================ */

/*
 * PCZT summary information returned by zsig_pczt_info
 */
typedef struct {
    uint32_t orchard_actions;
    uint32_t sapling_spends;
    uint32_t transparent_inputs;
    uint32_t transparent_outputs;
} ZsigPcztInfo;

/*
 * Extract summary information from a PCZT binary
 *
 * Parses the PCZT and returns counts of Orchard actions, Sapling spends,
 * transparent inputs, and transparent outputs. Useful for display on the
 * watch before the user confirms signing.
 *
 * Parameters:
 *   pczt_data: Pointer to raw PCZT binary data
 *   pczt_len: Length of PCZT data (max 1 MB)
 *   info_out: Pointer to receive the PCZT info (must not be NULL)
 *
 * Returns:
 *   ZSIG_SUCCESS on success
 *   ZSIG_ERROR_NULL_POINTER if any required pointer is NULL
 *   ZSIG_ERROR_BUFFER_TOO_SMALL if pczt_len is 0 or > 1MB
 *   ZSIG_ERROR_PCZT_PARSE_FAILED if the PCZT binary is invalid
 */
ZsigError zsig_pczt_info(const uint8_t* pczt_data,
                          size_t pczt_len,
                          ZsigPcztInfo* info_out);

/*
 * Sign a PCZT binary with the provided keys
 *
 * Parses the PCZT, signs all applicable spend types using the provided
 * keys, and writes the signed PCZT to the output buffer. The sighash is
 * computed internally from the PCZT data. Key pointers are optional —
 * pass NULL to skip signing for that protocol.
 *
 * The signed PCZT is typically the same size as the input (signatures
 * replace placeholder bytes). If output_len is too small, returns
 * ZSIG_ERROR_BUFFER_TOO_SMALL and writes the required size to
 * output_len_out.
 *
 * Parameters:
 *   pczt_data: Pointer to raw PCZT binary data
 *   pczt_len: Length of PCZT data (max 1 MB)
 *   sighash: Ignored (kept for ABI compatibility). May be NULL.
 *   orchard_sk: Pointer to 32-byte Orchard spending key (NULL to skip)
 *   sapling_ask: Pointer to 32-byte Sapling spend authorizing key (NULL to skip)
 *   transparent_sk: Pointer to 32-byte secp256k1 secret key (NULL to skip)
 *   output: Buffer for signed PCZT output
 *   output_len: Size of output buffer
 *   output_len_out: Receives actual length of signed PCZT
 *   rng: Ignored (kept for ABI compatibility)
 *
 * Returns:
 *   ZSIG_SUCCESS on success
 *   ZSIG_ERROR_NULL_POINTER if pczt_data, output, or output_len_out is NULL
 *   ZSIG_ERROR_BUFFER_TOO_SMALL if output_len is insufficient (check output_len_out)
 *   ZSIG_ERROR_PCZT_PARSE_FAILED if the PCZT binary is invalid
 *   ZSIG_ERROR_PCZT_INVALID_KEY if a provided key is malformed
 *   ZSIG_ERROR_PCZT_SIGN_FAILED if signing fails
 */
ZsigError zsig_pczt_sign(const uint8_t* pczt_data,
                          size_t pczt_len,
                          const uint8_t* sighash,
                          const uint8_t* orchard_sk,
                          const uint8_t* sapling_ask,
                          const uint8_t* transparent_sk,
                          uint8_t* output,
                          size_t output_len,
                          size_t* output_len_out,
                          ZsigRngCallback rng);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/*
 * BLAKE2b hash with 16-byte personalization
 *
 * Generic BLAKE2b hash function for F4Jumble decoding and other purposes.
 *
 * Parameters:
 *   personal: 16-byte personalization string
 *   personal_len: Must be 16
 *   data: Input data to hash
 *   data_len: Length of input data
 *   output: Output buffer for hash
 *   output_len: Desired output length (1-64)
 *
 * Returns:
 *   0 on success, -1 on error
 */
int32_t zsig_blake2b_personal(const uint8_t* personal,
                               size_t personal_len,
                               const uint8_t* data,
                               size_t data_len,
                               uint8_t* output,
                               size_t output_len);

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
