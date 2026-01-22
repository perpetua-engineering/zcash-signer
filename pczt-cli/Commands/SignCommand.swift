//
//  SignCommand.swift
//  pczt-cli
//
//  Sign sighashes with ASK (simulates watch device).
//  For transparent inputs, uses ZCASH_SEED env var if available.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit
import ZcashSignerCore
import CZcashSigner

struct SignCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sign",
        abstract: "Sign sighashes with ASK (watch simulation)"
    )

    @Argument(help: "ASK (hex string, 64 characters)")
    var ask: String

    @Argument(help: "Sighashes JSON file path")
    var sighashesFile: String

    mutating func run() async throws {
        errorOutput("[Sign] Loading sighashes from \(sighashesFile)...")

        // Load sighashes JSON
        let sighashesData = try Data(contentsOf: URL(fileURLWithPath: sighashesFile))
        let sighashesOutput = try JSON.decode(SighashesOutput.self, from: sighashesData)

        // Convert to SDK types
        guard let shieldedSighash = Data(hex: sighashesOutput.shieldedSighash) else {
            throw ValidationError("Invalid shielded sighash hex")
        }

        let orchardSpends = try sighashesOutput.orchardSpends.map { spend -> OrchardSpendInfo in
            guard let randomizer = Data(hex: spend.randomizer) else {
                throw ValidationError("Invalid randomizer hex at index \(spend.index)")
            }
            return OrchardSpendInfo(index: spend.index, randomizer: randomizer)
        }

        let saplingSpends = try sighashesOutput.saplingSpends.map { spend -> SaplingSpendInfo in
            guard let randomizer = Data(hex: spend.randomizer) else {
                throw ValidationError("Invalid randomizer hex at index \(spend.index)")
            }
            return SaplingSpendInfo(index: spend.index, randomizer: randomizer)
        }

        let transparentInputs = try sighashesOutput.transparentInputs.map { input -> TransparentInputInfo in
            guard let sighash = Data(hex: input.sighash) else {
                throw ValidationError("Invalid sighash hex at index \(input.index)")
            }
            guard let scriptPubKey = Data(hex: input.scriptPubKey) else {
                throw ValidationError("Invalid scriptPubKey hex at index \(input.index)")
            }
            return TransparentInputInfo(
                index: input.index,
                sighash: sighash,
                sighashType: input.sighashType,
                derivationPath: input.derivationPath,
                scriptPubKey: scriptPubKey,
                value: Zatoshi(Int64(input.value))
            )
        }

        let sighashes = PCZTSighashes(
            shieldedSighash: shieldedSighash,
            orchardSpends: orchardSpends,
            saplingSpends: saplingSpends,
            transparentInputs: transparentInputs
        )

        errorOutput("[Sign] Sighashes loaded:")
        errorOutput("[Sign]   Orchard spends: \(orchardSpends.count)")
        errorOutput("[Sign]   Sapling spends: \(saplingSpends.count)")
        errorOutput("[Sign]   Transparent inputs: \(transparentInputs.count)")

        // Sign with local signer
        let signer = try LocalSigner(askHex: ask)
        var signatures = try signer.sign(sighashes: sighashes)

        // If there are transparent inputs and we have ZCASH_SEED, sign them
        if !transparentInputs.isEmpty {
            if let seed = try? SeedManager.parseSeed() {
                errorOutput("[Sign] Using ZCASH_SEED for transparent signing...")
                let transparentSigs = try signTransparentInputs(
                    inputs: sighashesOutput.transparentInputs,
                    seed: seed
                )
                signatures = PCZTSignatures(
                    orchardSignatures: signatures.orchardSignatures,
                    saplingSignatures: signatures.saplingSignatures,
                    transparentSignatures: transparentSigs
                )
                errorOutput("[Sign] Signed \(transparentSigs.count) transparent inputs")
            } else {
                errorOutput("[Sign] Warning: ZCASH_SEED not set, transparent inputs will not be signed")
                errorOutput("[Sign] Set ZCASH_SEED environment variable for transparent signing")
            }
        }

        errorOutput("[Sign] Signed \(signatures.orchardSignatures.count) Orchard spends")

        // Output signatures
        let output = SignaturesInput(
            orchardSignatures: signatures.orchardSignatures.map {
                ShieldedSignatureInput(index: $0.index, signature: $0.signature.hexString)
            },
            saplingSignatures: signatures.saplingSignatures.map {
                ShieldedSignatureInput(index: $0.index, signature: $0.signature.hexString)
            },
            transparentSignatures: signatures.transparentSignatures.map {
                TransparentSignatureInput(
                    index: $0.index,
                    signature: $0.signature.hexString,
                    publicKey: $0.publicKey.hexString,
                    sighashType: $0.sighashType
                )
            }
        )
        try outputJSON(output)
    }

    private func signTransparentInputs(
        inputs: [TransparentInputOutput],
        seed: Data
    ) throws -> [TransparentSignature] {
        // For now, use a placeholder - we need FFI support for secp256k1 signing
        // The derivation path in the sighashes tells us which key to use
        var signatures: [TransparentSignature] = []

        for input in inputs {
            guard let sighash = Data(hex: input.sighash) else {
                throw ValidationError("Invalid sighash hex at index \(input.index)")
            }

            // Derive the transparent key and sign
            // Default path for account 0, external chain, index 0: m/44'/133'/0'/0/0
            let path: [UInt32]
            if input.derivationPath.isEmpty {
                path = [
                    UInt32(44) | 0x80000000,
                    UInt32(133) | 0x80000000,
                    UInt32(0) | 0x80000000,
                    0,
                    0
                ]
            } else {
                path = input.derivationPath
            }

            let (signature, publicKey) = try signTransparent(
                seed: seed,
                derivationPath: path,
                sighash: sighash,
                sighashType: input.sighashType
            )

            signatures.append(TransparentSignature(
                index: input.index,
                signature: signature,
                publicKey: publicKey,
                sighashType: input.sighashType
            ))
        }

        return signatures
    }

    private func signTransparent(
        seed: Data,
        derivationPath: [UInt32],
        sighash: Data,
        sighashType: UInt8
    ) throws -> (signature: Data, publicKey: Data) {
        // Use the FFI function for transparent signing
        var signatureBuffer = [UInt8](repeating: 0, count: 72)
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

        guard result == ZSIG_SUCCESS else {
            throw LocalSignerError.signingFailed("Transparent signing failed with error \(result)")
        }

        return (
            signature: Data(signatureBuffer.prefix(signatureLen)),
            publicKey: Data(pubkeyBuffer)
        )
    }
}
