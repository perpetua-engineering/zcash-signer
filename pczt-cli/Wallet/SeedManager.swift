//
//  SeedManager.swift
//  pczt-cli
//
//  Handles seed parsing from ZCASH_SEED environment variable.
//  Supports BIP-39 mnemonic phrases and 64-byte hex seeds.
//

import Foundation
import Darwin

// MARK: - Seed Manager

struct SeedManager {
    /// Parse seed from ZCASH_SEED environment variable.
    /// Supports:
    /// - 24-word BIP-39 mnemonic phrase (space or newline separated)
    /// - 64-byte hex string (128 characters)
    static func parseSeed() throws -> Data {
        guard let seedEnv = ProcessInfo.processInfo.environment["ZCASH_SEED"] else {
            throw SeedError.missingEnvironmentVariable
        }

        let trimmed = seedEnv.trimmingCharacters(in: .whitespacesAndNewlines)

        // Check if it's a hex seed (128 hex characters = 64 bytes)
        if trimmed.count == 128, let hexData = Data(hex: trimmed) {
            return hexData
        }

        // Otherwise, treat as BIP-39 mnemonic
        let words = trimmed.components(separatedBy: .whitespacesAndNewlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard words.count == 24 else {
            throw SeedError.invalidMnemonic("Expected 24 words, got \(words.count)")
        }

        // Derive seed from mnemonic using BIP-39
        let mnemonic = words.joined(separator: " ")
        return try deriveSeedFromMnemonic(mnemonic)
    }

    /// Derive a 64-byte seed from a BIP-39 mnemonic phrase.
    /// Uses PBKDF2-HMAC-SHA512 with "mnemonic" as the salt (no passphrase).
    private static func deriveSeedFromMnemonic(_ mnemonic: String, passphrase: String = "") throws -> Data {
        let password = mnemonic.decomposedStringWithCompatibilityMapping
        let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping

        guard let passwordData = password.data(using: .utf8),
              let saltData = salt.data(using: .utf8) else {
            throw SeedError.invalidMnemonic("Failed to encode mnemonic")
        }

        // PBKDF2-HMAC-SHA512 with 2048 iterations, 64-byte output
        let seed = try pbkdf2(
            password: passwordData,
            salt: saltData,
            iterations: 2048,
            keyLength: 64
        )

        return seed
    }

    // CommonCrypto constants
    private static let kCCSuccess: Int32 = 0
    private static let kCCPBKDF2: UInt32 = 2
    private static let kCCPRFHmacAlgSHA512: UInt32 = 5

    /// PBKDF2-HMAC-SHA512 implementation using CommonCrypto.
    private static func pbkdf2(password: Data, salt: Data, iterations: Int, keyLength: Int) throws -> Data {
        var derivedKey = Data(count: keyLength)

        let result = derivedKey.withUnsafeMutableBytes { derivedKeyPtr in
            password.withUnsafeBytes { passwordPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        kCCPBKDF2,
                        passwordPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        kCCPRFHmacAlgSHA512,
                        UInt32(iterations),
                        derivedKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw SeedError.derivationFailed("PBKDF2 failed with error \(result)")
        }

        return derivedKey
    }
}

// MARK: - CommonCrypto Binding

@_silgen_name("CCKeyDerivationPBKDF")
private func CCKeyDerivationPBKDF(
    _ algorithm: UInt32,
    _ password: UnsafePointer<Int8>?,
    _ passwordLen: Int,
    _ salt: UnsafePointer<UInt8>?,
    _ saltLen: Int,
    _ prf: UInt32,
    _ rounds: UInt32,
    _ derivedKey: UnsafeMutablePointer<UInt8>?,
    _ derivedKeyLen: Int
) -> Int32

// MARK: - Errors

enum SeedError: Error, LocalizedError {
    case missingEnvironmentVariable
    case invalidMnemonic(String)
    case derivationFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingEnvironmentVariable:
            return "ZCASH_SEED environment variable is not set"
        case .invalidMnemonic(let reason):
            return "Invalid mnemonic: \(reason)"
        case .derivationFailed(let reason):
            return "Seed derivation failed: \(reason)"
        }
    }
}
