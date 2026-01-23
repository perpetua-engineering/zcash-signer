//
//  ZcashSignerWrapper.swift
//  ZcashSigner
//
//  Swift wrapper for the ZcashSigner Rust library
//  Provides ZIP-32 key derivation and RedPallas signing for Orchard
//

import Foundation
import Security
@_implementationOnly import CZcashSigner

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
