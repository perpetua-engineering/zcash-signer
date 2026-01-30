//
//  ZcashSignerWrapper.swift
//  ZcashSigner
//
//  Swift wrapper for the ZcashSigner Rust library
//  Provides ZIP-32 key derivation and RedPallas signing for Orchard
//

import Foundation
import Security
@_implementationOnly import ZcashSigner

// MARK: - Error Types

/// Errors from ZcashSigner operations
public enum ZcashSignerError: Error, LocalizedError {
    case nullPointer
    case invalidKey
    case invalidSeed
    case signingFailed
    case invalidSignature
    case rngFailed
    case scalarConversionFailed
    case pointConversionFailed
    case bufferTooSmall
    case unknown(UInt32)

    init(code: UInt32) {
        switch code {
        case 0: self = .invalidKey // Should not happen, 0 is success
        case 1: self = .nullPointer
        case 2: self = .invalidKey
        case 3: self = .invalidSeed
        case 4: self = .signingFailed
        case 5: self = .invalidSignature
        case 6: self = .rngFailed
        case 7: self = .scalarConversionFailed
        case 8: self = .pointConversionFailed
        case 9: self = .bufferTooSmall
        default: self = .unknown(code)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .nullPointer: return "Null pointer passed to function"
        case .invalidKey: return "Invalid key format"
        case .invalidSeed: return "Invalid seed length (must be 32-252 bytes for ZIP-32)"
        case .signingFailed: return "Signing operation failed"
        case .invalidSignature: return "Invalid signature format"
        case .rngFailed: return "Random number generation failed"
        case .scalarConversionFailed: return "Scalar conversion failed"
        case .pointConversionFailed: return "Point conversion failed"
        case .bufferTooSmall: return "Output buffer too small"
        case .unknown(let code): return "Unknown error code: \(code)"
        }
    }
}

// MARK: - Zcash Mainnet Coin Type

/// Zcash mainnet coin type (BIP-44 / ZIP-32)
public let ZSIG_MAINNET_COIN_TYPE: UInt32 = 133

// MARK: - Key Types

/// Orchard spending key (32 bytes)
/// Derived via ZIP-32 path: m/32'/coin_type'/account'
public struct ZcashOrchardSpendingKey {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        self.bytes = bytes
    }

    /// Derive an Orchard spending key from a BIP-39 seed using ZIP-32
    ///
    /// Path: m/32'/coin_type'/account'
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: ZSIG_MAINNET_COIN_TYPE = 133)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived Orchard spending key
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashOrchardSpendingKey {
        var key = ZsigOrchardSpendingKey()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_orchard_spending_key(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &key
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashOrchardSpendingKey(bytes: Data(bytes: &key.bytes, count: 32))
    }

    /// Derive the spend authorization key (ask) from this spending key
    public func deriveAsk() throws -> ZcashOrchardAsk {
        var spendingKey = ZsigOrchardSpendingKey()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&spendingKey.bytes, ptr.baseAddress!, 32)
        }

        var ask = ZsigOrchardAsk()
        let result = zsig_derive_orchard_ask(&spendingKey, &ask)

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashOrchardAsk(bytes: Data(bytes: &ask.bytes, count: 32))
    }
}

/// Orchard spend authorization key "ask" (32-byte scalar on Pallas)
/// This is the key used for signing Orchard transactions
public struct ZcashOrchardAsk {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        self.bytes = bytes
    }

    /// Derive ask directly from a BIP-39 seed
    ///
    /// This is a convenience function that combines spending key derivation and ask derivation.
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: ZSIG_MAINNET_COIN_TYPE = 133)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived spend authorization key
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashOrchardAsk {
        var ask = ZsigOrchardAsk()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_orchard_ask_from_seed(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &ask
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashOrchardAsk(bytes: Data(bytes: &ask.bytes, count: 32))
    }

    /// Derive the authorization key (ak) from this ask
    ///
    /// ak = ask * G where G is the Orchard SpendAuth basepoint
    ///
    /// - Returns: The 32-byte authorization key
    public func deriveAk() throws -> Data {
        var askFFI = ZsigOrchardAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var ak = [UInt8](repeating: 0, count: 32)
        let result = zsig_derive_ak_from_ask(&askFFI, &ak)

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(ak)
    }

    /// Sign a sighash using RedPallas with a randomized key (PCZT signing)
    ///
    /// For PCZT signing, each Orchard spend has an alpha randomizer.
    /// The signature verifies against rk = ak + [alpha]G, so we sign with
    /// the randomized key: ask_randomized = ask + alpha.
    ///
    /// - Parameters:
    ///   - sighash: The 32-byte transaction sighash
    ///   - alpha: The 32-byte alpha randomizer from the PCZT
    /// - Returns: The 64-byte RedPallas signature
    public func signRandomized(sighash: Data, alpha: Data) throws -> Data {
        guard sighash.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        guard alpha.count == 32 else {
            throw ZcashSignerError.invalidKey
        }

        var askFFI = ZsigOrchardAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var signature = ZsigOrchardSignature()

        let result = sighash.withUnsafeBytes { sighashPtr in
            alpha.withUnsafeBytes { alphaPtr in
                zsig_sign_orchard_randomized(
                    &askFFI,
                    alphaPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sighashPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &signature,
                    secureRandomCallback
                )
            }
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(bytes: &signature.bytes, count: 64)
    }

    /// Sign a message using RedPallas (non-randomized, for testing)
    ///
    /// - Parameter message: The message to sign
    /// - Returns: The 64-byte RedPallas signature
    public func sign(message: Data) throws -> Data {
        var askFFI = ZsigOrchardAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var signature = ZsigOrchardSignature()

        let result = message.withUnsafeBytes { msgPtr in
            zsig_sign_orchard(
                &askFFI,
                msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                message.count,
                &signature,
                secureRandomCallback
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(bytes: &signature.bytes, count: 64)
    }
}

// MARK: - Sapling Spend Authorization Key

/// Sapling spend authorization key (ask)
///
/// This is the key used to sign Sapling spends in PCZT transactions.
/// Uses RedJubjub signatures on the Jubjub curve.
public struct ZcashSaplingAsk {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        self.bytes = bytes
    }

    /// Derive ask directly from a BIP-39 seed
    ///
    /// This is a convenience function that combines spending key derivation and ask derivation.
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: ZSIG_MAINNET_COIN_TYPE = 133)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived Sapling spend authorization key
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashSaplingAsk {
        var ask = ZsigSaplingAsk()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_sapling_ask_from_seed(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &ask
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashSaplingAsk(bytes: Data(bytes: &ask.bytes, count: 32))
    }

    /// Derive the authorization key (ak) from this ask
    ///
    /// ak = ask * G where G is the Sapling SpendAuth basepoint
    ///
    /// - Returns: The 32-byte authorization key
    public func deriveAk() throws -> Data {
        var askFFI = ZsigSaplingAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var ak = [UInt8](repeating: 0, count: 32)
        let result = zsig_derive_sapling_ak_from_ask(&askFFI, &ak)

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(ak)
    }

    /// Sign a sighash using RedJubjub with a randomized key (PCZT signing)
    ///
    /// For PCZT signing, each Sapling spend has an alpha randomizer.
    /// The signature verifies against rk = ak + [alpha]G, so we sign with
    /// the randomized key: ask_randomized = ask + alpha.
    ///
    /// - Parameters:
    ///   - sighash: The 32-byte transaction sighash
    ///   - alpha: The 32-byte alpha randomizer from the PCZT
    /// - Returns: The 64-byte RedJubjub signature
    public func signRandomized(sighash: Data, alpha: Data) throws -> Data {
        guard sighash.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        guard alpha.count == 32 else {
            throw ZcashSignerError.invalidKey
        }

        var askFFI = ZsigSaplingAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var signature = ZsigSaplingSignature()

        let result = sighash.withUnsafeBytes { sighashPtr in
            alpha.withUnsafeBytes { alphaPtr in
                zsig_sign_sapling_randomized(
                    &askFFI,
                    alphaPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sighashPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &signature,
                    secureRandomCallback
                )
            }
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(bytes: &signature.bytes, count: 64)
    }

    /// Sign a message using RedJubjub (non-randomized, for testing)
    ///
    /// - Parameter message: The message to sign
    /// - Returns: The 64-byte RedJubjub signature
    public func sign(message: Data) throws -> Data {
        var askFFI = ZsigSaplingAsk()
        bytes.withUnsafeBytes { ptr in
            _ = memcpy(&askFFI.bytes, ptr.baseAddress!, 32)
        }

        var signature = ZsigSaplingSignature()

        let result = message.withUnsafeBytes { msgPtr in
            zsig_sign_sapling(
                &askFFI,
                msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                message.count,
                &signature,
                secureRandomCallback
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return Data(bytes: &signature.bytes, count: 64)
    }
}

// MARK: - Diversifier Derivation

/// Derive the first valid Sapling diversifier index from a BIP-39 seed
///
/// This function derives the Sapling diversifier key (dk) from the seed,
/// then searches for the first index where the diversifier produces a valid
/// Sapling address. This index should be used for all receiver types in a
/// Unified Address to comply with ZIP-316.
///
/// - Parameters:
///   - seed: The BIP-39 seed (typically 64 bytes)
///   - coinType: Coin type for derivation (default: 133 for mainnet)
///   - account: Account index (default: 0)
/// - Returns: Tuple of (first valid diversifier index, 11-byte diversifier)
public func deriveFirstValidDiversifierIndex(
    seed: Data,
    coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
    account: UInt32 = 0
) throws -> (index: UInt64, diversifier: Data) {
    var index: UInt64 = 0
    var diversifier = [UInt8](repeating: 0, count: 11)

    let result = seed.withUnsafeBytes { seedPtr in
        zsig_derive_first_valid_diversifier_index(
            seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
            seed.count,
            coinType,
            account,
            &index,
            &diversifier
        )
    }

    guard result.rawValue == 0 else {
        throw ZcashSignerError(code: result.rawValue)
    }

    return (index: index, diversifier: Data(diversifier))
}

// MARK: - Transparent Address Derivation

/// Derive a transparent P2PKH address from seed using BIP-44
///
/// Path: m/44'/133'/account'/0/index
///
/// - Parameters:
///   - seed: The BIP-39 seed (typically 64 bytes)
///   - account: Account index (default: 0)
///   - index: Address index (0 for first address)
///   - mainnet: true for mainnet (t1...), false for testnet (tm...)
/// - Returns: The transparent address string (e.g., "t1...")
public func deriveTransparentAddress(
    seed: Data,
    account: UInt32 = 0,
    index: UInt32 = 0,
    mainnet: Bool = true
) throws -> String {
    var output = [UInt8](repeating: 0, count: 64)

    let len = seed.withUnsafeBytes { seedPtr in
        zsig_derive_transparent_address(
            seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
            seed.count,
            account,
            index,
            mainnet,
            &output,
            64
        )
    }

    guard len > 0 else {
        throw ZcashSignerError.invalidKey
    }

    guard let address = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
        throw ZcashSignerError.invalidKey
    }

    return address
}

/// Derive transparent pubkey hash (20 bytes) from seed
///
/// This is useful for creating Unified Addresses with a transparent receiver.
///
/// - Parameters:
///   - seed: The BIP-39 seed (typically 64 bytes)
///   - account: Account index (default: 0)
///   - index: Address index (0 for first address)
/// - Returns: The 20-byte pubkey hash
public func deriveTransparentPubkeyHash(
    seed: Data,
    account: UInt32 = 0,
    index: UInt32 = 0
) throws -> Data {
    var hash = [UInt8](repeating: 0, count: 20)

    let result = seed.withUnsafeBytes { seedPtr in
        zsig_derive_transparent_pubkey_hash(
            seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
            seed.count,
            account,
            index,
            &hash
        )
    }

    guard result.rawValue == 0 else {
        throw ZcashSignerError(code: result.rawValue)
    }

    return Data(hash)
}

// MARK: - Transparent Signing

/// Sign a transparent input using BIP-44 derived key (secp256k1/ECDSA)
///
/// This produces a DER-encoded signature with sighash type byte appended,
/// suitable for use in a transparent input's scriptSig.
///
/// - Parameters:
///   - seed: BIP-39 seed (typically 64 bytes)
///   - derivationPath: BIP-32 path components with hardened bits (e.g., [0x8000002C, 0x80000085, 0x80000000, 0, 0])
///   - sighash: 32-byte sighash to sign
///   - sighashType: Sighash type byte (default 0x01 = SIGHASH_ALL)
/// - Returns: Tuple of (DER signature with sighash type appended, compressed 33-byte pubkey)
public func signTransparent(
    seed: Data,
    derivationPath: [UInt32],
    sighash: Data,
    sighashType: UInt8 = 0x01
) throws -> (signature: Data, pubkey: Data) {
    guard sighash.count == 32 else {
        throw ZcashSignerError.invalidKey
    }
    guard !derivationPath.isEmpty else {
        throw ZcashSignerError.invalidKey
    }

    // DER signature can be up to 72 bytes + 1 byte sighash type
    var signatureBuffer = [UInt8](repeating: 0, count: 73)
    var signatureLen: Int = 0
    var pubkeyBuffer = [UInt8](repeating: 0, count: 33)

    let result = seed.withUnsafeBytes { seedPtr in
        derivationPath.withUnsafeBufferPointer { pathPtr in
            sighash.withUnsafeBytes { sighashPtr in
                zsig_sign_transparent(
                    seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    seed.count,
                    pathPtr.baseAddress,
                    derivationPath.count,
                    sighashPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sighashType,
                    &signatureBuffer,
                    &signatureLen,
                    &pubkeyBuffer
                )
            }
        }
    }

    guard result.rawValue == 0 else {
        throw ZcashSignerError(code: result.rawValue)
    }

    // The Rust function returns DER signature without sighash type,
    // we need to append it
    var signature = Data(signatureBuffer.prefix(signatureLen))
    signature.append(sighashType)

    return (signature: signature, pubkey: Data(pubkeyBuffer))
}

// MARK: - Orchard Address

/// Orchard payment address (diversifier + pk_d)
public struct ZcashOrchardAddress {
    /// 11-byte diversifier
    public let diversifier: Data
    /// 32-byte diversified transmission key
    public let pkD: Data

    public init(diversifier: Data, pkD: Data) throws {
        guard diversifier.count == 11 else {
            throw ZcashSignerError.invalidKey
        }
        guard pkD.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        self.diversifier = diversifier
        self.pkD = pkD
    }

    /// Derive an Orchard address from a BIP-39 seed
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: 133 for mainnet)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived Orchard address
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashOrchardAddress {
        var address = ZsigOrchardAddress()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_orchard_address_from_seed(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &address
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashOrchardAddress(
            diversifier: Data(bytes: &address.diversifier, count: 11),
            pkD: Data(bytes: &address.pk_d, count: 32)
        )
    }

    /// Encode as a Unified Address string
    ///
    /// - Parameter mainnet: true for mainnet (u...), false for testnet (utest...)
    /// - Returns: The encoded Unified Address string
    public func encodeUnifiedAddress(mainnet: Bool = true) throws -> String {
        var address = ZsigOrchardAddress()
        diversifier.withUnsafeBytes { ptr in
            _ = memcpy(&address.diversifier, ptr.baseAddress!, 11)
        }
        pkD.withUnsafeBytes { ptr in
            _ = memcpy(&address.pk_d, ptr.baseAddress!, 32)
        }

        var output = [UInt8](repeating: 0, count: 256)

        let len = zsig_encode_unified_address(&address, mainnet, &output, 256)

        guard len > 0 else {
            throw ZcashSignerError.bufferTooSmall
        }

        guard let ua = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
            throw ZcashSignerError.invalidKey
        }

        return ua
    }

    /// Encode as a Unified Address with a transparent receiver
    ///
    /// This creates a UA that CEXs can use - they'll send to the transparent receiver
    /// if they don't support Orchard.
    ///
    /// - Parameters:
    ///   - transparentPubkeyHash: 20-byte transparent pubkey hash
    ///   - mainnet: true for mainnet, false for testnet
    /// - Returns: The encoded Unified Address string
    public func encodeUnifiedAddressWithTransparent(
        transparentPubkeyHash: Data,
        mainnet: Bool = true
    ) throws -> String {
        guard transparentPubkeyHash.count == 20 else {
            throw ZcashSignerError.invalidKey
        }

        var address = ZsigOrchardAddress()
        diversifier.withUnsafeBytes { ptr in
            _ = memcpy(&address.diversifier, ptr.baseAddress!, 11)
        }
        pkD.withUnsafeBytes { ptr in
            _ = memcpy(&address.pk_d, ptr.baseAddress!, 32)
        }

        var output = [UInt8](repeating: 0, count: 256)

        let len = transparentPubkeyHash.withUnsafeBytes { pkhPtr in
            zsig_encode_unified_address_with_transparent(
                &address,
                pkhPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                mainnet,
                &output,
                256
            )
        }

        guard len > 0 else {
            throw ZcashSignerError.bufferTooSmall
        }

        guard let ua = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
            throw ZcashSignerError.invalidKey
        }

        return ua
    }
}

// MARK: - Full Viewing Key

/// Orchard Full Viewing Key components
public struct ZcashOrchardFullViewingKey {
    /// 32-byte authorization key
    public let ak: Data
    /// 32-byte nullifier deriving key
    public let nk: Data
    /// 32-byte randomized ivk
    public let rivk: Data

    public init(ak: Data, nk: Data, rivk: Data) throws {
        guard ak.count == 32, nk.count == 32, rivk.count == 32 else {
            throw ZcashSignerError.invalidKey
        }
        self.ak = ak
        self.nk = nk
        self.rivk = rivk
    }

    /// Derive an Orchard FVK from a BIP-39 seed
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: 133 for mainnet)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived FVK
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashOrchardFullViewingKey {
        var fvk = ZsigOrchardFullViewingKey()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_orchard_full_viewing_key(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &fvk
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        return try ZcashOrchardFullViewingKey(
            ak: Data(bytes: &fvk.ak, count: 32),
            nk: Data(bytes: &fvk.nk, count: 32),
            rivk: Data(bytes: &fvk.rivk, count: 32)
        )
    }

    /// Encode as a Unified Full Viewing Key string
    ///
    /// - Parameter mainnet: true for mainnet (uview...), false for testnet (uviewtest...)
    /// - Returns: The encoded UFVK string
    public func encodeUFVK(mainnet: Bool = true) throws -> String {
        var fvk = ZsigOrchardFullViewingKey()
        ak.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.ak, ptr.baseAddress!, 32)
        }
        nk.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.nk, ptr.baseAddress!, 32)
        }
        rivk.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.rivk, ptr.baseAddress!, 32)
        }

        var output = [UInt8](repeating: 0, count: 512)

        let len = zsig_encode_unified_full_viewing_key(&fvk, mainnet, &output, 512)

        guard len > 0 else {
            throw ZcashSignerError.bufferTooSmall
        }

        guard let ufvk = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
            throw ZcashSignerError.invalidKey
        }

        return ufvk
    }
}

/// Derive UFVK string directly from seed (convenience function)
///
/// - Parameters:
///   - seed: The BIP-39 seed (typically 64 bytes)
///   - coinType: Coin type for derivation (default: 133 for mainnet)
///   - account: Account index (default: 0)
///   - mainnet: true for mainnet, false for testnet
/// - Returns: The encoded UFVK string
public func deriveUFVKString(
    seed: Data,
    coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
    account: UInt32 = 0,
    mainnet: Bool = true
) throws -> String {
    var output = [UInt8](repeating: 0, count: 512)

    let len = seed.withUnsafeBytes { seedPtr in
        zsig_derive_ufvk_string(
            seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
            seed.count,
            coinType,
            account,
            mainnet,
            &output,
            512
        )
    }

    guard len > 0 else {
        throw ZcashSignerError(code: UInt32(-len))
    }

    guard let ufvk = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
        throw ZcashSignerError.invalidKey
    }

    return ufvk
}

// MARK: - Combined UFVK (Orchard + Transparent)

/// Combined Full Viewing Key (Orchard + Transparent)
public struct ZcashCombinedFullViewingKey {
    /// Orchard FVK components
    public let orchard: ZcashOrchardFullViewingKey
    /// Transparent chain code (32 bytes)
    public let transparentChainCode: Data
    /// Transparent compressed pubkey (33 bytes)
    public let transparentPubkey: Data

    public init(orchard: ZcashOrchardFullViewingKey, transparentChainCode: Data, transparentPubkey: Data) throws {
        guard transparentChainCode.count == 32, transparentPubkey.count == 33 else {
            throw ZcashSignerError.invalidKey
        }
        self.orchard = orchard
        self.transparentChainCode = transparentChainCode
        self.transparentPubkey = transparentPubkey
    }

    /// Derive a combined FVK from a BIP-39 seed
    ///
    /// - Parameters:
    ///   - seed: The BIP-39 seed (typically 64 bytes)
    ///   - coinType: Coin type for derivation (default: 133 for mainnet)
    ///   - account: Account index (default: 0)
    /// - Returns: The derived combined FVK
    public static func deriveFromSeed(
        _ seed: Data,
        coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
        account: UInt32 = 0
    ) throws -> ZcashCombinedFullViewingKey {
        var fvk = ZsigCombinedFullViewingKey()

        let result = seed.withUnsafeBytes { seedPtr in
            zsig_derive_combined_full_viewing_key(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                coinType,
                account,
                &fvk
            )
        }

        guard result.rawValue == 0 else {
            throw ZcashSignerError(code: result.rawValue)
        }

        let orchardFvk = try ZcashOrchardFullViewingKey(
            ak: Data(bytes: &fvk.orchard.ak, count: 32),
            nk: Data(bytes: &fvk.orchard.nk, count: 32),
            rivk: Data(bytes: &fvk.orchard.rivk, count: 32)
        )

        return try ZcashCombinedFullViewingKey(
            orchard: orchardFvk,
            transparentChainCode: Data(bytes: &fvk.transparent.chain_code, count: 32),
            transparentPubkey: Data(bytes: &fvk.transparent.pubkey, count: 33)
        )
    }

    /// Encode as a Unified Full Viewing Key string
    ///
    /// - Parameter mainnet: true for mainnet (uview...), false for testnet (uviewtest...)
    /// - Returns: The encoded UFVK string
    public func encodeUFVK(mainnet: Bool = true) throws -> String {
        var fvk = ZsigCombinedFullViewingKey()
        orchard.ak.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.orchard.ak, ptr.baseAddress!, 32)
        }
        orchard.nk.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.orchard.nk, ptr.baseAddress!, 32)
        }
        orchard.rivk.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.orchard.rivk, ptr.baseAddress!, 32)
        }
        transparentChainCode.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.transparent.chain_code, ptr.baseAddress!, 32)
        }
        transparentPubkey.withUnsafeBytes { ptr in
            _ = memcpy(&fvk.transparent.pubkey, ptr.baseAddress!, 33)
        }

        var output = [UInt8](repeating: 0, count: 512)

        let len = zsig_encode_combined_full_viewing_key(&fvk, mainnet, &output, 512)

        guard len > 0 else {
            throw ZcashSignerError.bufferTooSmall
        }

        guard let ufvk = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
            throw ZcashSignerError.invalidKey
        }

        return ufvk
    }
}

/// Derive Combined UFVK string directly from seed (convenience function)
///
/// This is the recommended function for deriving a UFVK that includes both
/// Orchard and transparent receivers, enabling full balance viewing in wallets
/// like Zashi.
///
/// - Parameters:
///   - seed: The BIP-39 seed (typically 64 bytes)
///   - coinType: Coin type for derivation (default: 133 for mainnet)
///   - account: Account index (default: 0)
///   - mainnet: true for mainnet, false for testnet
/// - Returns: The encoded combined UFVK string
public func deriveCombinedUFVKString(
    seed: Data,
    coinType: UInt32 = ZSIG_MAINNET_COIN_TYPE,
    account: UInt32 = 0,
    mainnet: Bool = true
) throws -> String {
    var output = [UInt8](repeating: 0, count: 512)

    let len = seed.withUnsafeBytes { seedPtr in
        zsig_derive_combined_ufvk_string(
            seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
            seed.count,
            coinType,
            account,
            mainnet,
            &output,
            512
        )
    }

    guard len > 0 else {
        throw ZcashSignerError(code: UInt32(-len))
    }

    guard let ufvk = String(bytes: output.prefix(Int(len)), encoding: .utf8) else {
        throw ZcashSignerError.invalidKey
    }

    return ufvk
}

// MARK: - RNG Callback

/// Callback for SecRandomCopyBytes, passed to Rust library
private func secureRandomCallback(buffer: UnsafeMutablePointer<UInt8>?, length: Int) -> Int32 {
    guard let buffer = buffer else { return 1 }

    let status = SecRandomCopyBytes(kSecRandomDefault, length, buffer)
    return status == errSecSuccess ? 0 : 1
}

// MARK: - Version Info

/// Get the ZcashSigner library version
public func zcashSignerVersion() -> String {
    guard let versionPtr = zsig_version() else {
        return "unknown"
    }
    return String(cString: versionPtr)
}
