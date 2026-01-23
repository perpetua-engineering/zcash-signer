//
//  SignCommand.swift
//  pczt-cli
//
//  Sign sighashes with ASK (simulates watch device).
//  For transparent inputs, uses ZCASH_SEED env var if available.
//

import ArgumentParser
import Foundation
import Darwin
import ZcashLightClientKit
import ZcashSignerCore
import CZcashSigner

private final class ToolsSigner {
    typealias OrchardSignFn = @convention(c) (
        UnsafePointer<UInt8>,
        Int,
        UInt32,
        UnsafePointer<UInt8>,
        Int,
        UnsafePointer<UInt8>,
        Int,
        UnsafeMutablePointer<UInt8>
    ) -> Bool

    private let handle: UnsafeMutableRawPointer
    private let orchardSign: OrchardSignFn

    init?(path: String) {
        guard let handle = dlopen(path, RTLD_NOW) else {
            return nil
        }
        guard let sym = dlsym(handle, "zcash_signer_orchard_signature") else {
            dlclose(handle)
            return nil
        }
        self.handle = handle
        self.orchardSign = unsafeBitCast(sym, to: OrchardSignFn.self)
    }

    deinit {
        dlclose(handle)
    }

    func signOrchard(seed: Data, account: UInt32, sighash: Data, randomizer: Data) throws -> Data {
        guard sighash.count == 32, randomizer.count == 32 else {
            throw ValidationError("Invalid orchard sighash/randomizer length")
        }

        var signature = [UInt8](repeating: 0, count: 64)
        let ok = seed.withUnsafeBytes { seedPtr in
            sighash.withUnsafeBytes { sighashPtr in
                randomizer.withUnsafeBytes { randomizerPtr in
                    orchardSign(
                        seedPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        seed.count,
                        account,
                        sighashPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        sighash.count,
                        randomizerPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        randomizer.count,
                        &signature
                    )
                }
            }
        }

        guard ok else {
            throw ValidationError("Tools signer failed to sign Orchard spend")
        }

        return Data(signature)
    }
}

struct SignCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sign",
        abstract: "Sign sighashes with ASK (watch simulation)"
    )

    enum SignerMode: String, ExpressibleByArgument {
        case ask
        case tools
        case compare
    }

    @Argument(help: "ASK (hex string, 64 characters)")
    var ask: String

    @Argument(help: "Sighashes JSON file path")
    var sighashesFile: String

    @Option(name: .long, help: "Signer mode: ask (default), tools, compare")
    var signer: SignerMode = .ask

    @Option(name: .long, help: "Account index for seed-based signing")
    var account: UInt32 = 0

    @Option(
        name: .long,
        help: "Path to Tools/ZcashSigner dylib (for tools/compare modes)"
    )
    var toolsSignerPath: String = "../zcash-swift-wallet-sdk/Tools/ZcashSigner/target/release/libzcash_signer.dylib"

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

        var signatures: PCZTSignatures
        let seedForTools: Data?
        if signer != .ask {
            seedForTools = try? SeedManager.parseSeed()
            if seedForTools == nil {
                throw ValidationError("ZCASH_SEED required for signer mode \(signer.rawValue)")
            }
        } else {
            seedForTools = nil
        }

        if let seed = seedForTools, StateManager.shared.walletConfigExists() {
            do {
                let config = try StateManager.shared.loadWalletConfig()
                let derivedUfvk = try deriveUFVK(seed: seed, account: account, network: config.network)
                if derivedUfvk != config.ufvk {
                    errorOutput("[Sign] Warning: UFVK derived from ZCASH_SEED does not match saved wallet config")
                } else {
                    errorOutput("[Sign] UFVK matches saved wallet config")
                }
            } catch {
                errorOutput("[Sign] Warning: failed to compare UFVK with saved config: \(error)")
            }
        }

        switch signer {
        case .ask:
            let localSigner = try LocalSigner(askHex: ask)
            signatures = try localSigner.sign(sighashes: sighashes)
        case .tools, .compare:
            guard let seed = seedForTools else {
                throw ValidationError("ZCASH_SEED required for tools signer")
            }
            guard let toolsSigner = ToolsSigner(path: toolsSignerPath) else {
                throw ValidationError("Failed to load tools signer dylib at \(toolsSignerPath)")
            }

            let orchardSigs = try sighashes.orchardSpends.map { spend -> ShieldedSignature in
                let signature = try toolsSigner.signOrchard(
                    seed: seed,
                    account: account,
                    sighash: sighashes.shieldedSighash,
                    randomizer: spend.randomizer
                )
                return ShieldedSignature(index: spend.index, signature: signature)
            }

            if signer == .compare {
                let localSigner = try LocalSigner(askHex: ask)
                let localSigs = try localSigner.sign(sighashes: sighashes).orchardSignatures
                for sig in orchardSigs {
                    if let local = localSigs.first(where: { $0.index == sig.index }) {
                        if local.signature != sig.signature {
                            errorOutput("[Sign] Orchard signature mismatch at index \(sig.index)")
                        }
                    }
                }
            }

            signatures = PCZTSignatures(
                orchardSignatures: orchardSigs,
                saplingSignatures: [],
                transparentSignatures: []
            )
        }

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
                let scriptPreview = input.scriptPubKey.prefix(16)
                errorOutput("[Sign] Warning: derivation path missing for input \(input.index); using default \(path). scriptPubKey=\(scriptPreview)...")
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

    private func deriveUFVK(seed: Data, account: UInt32, network: WalletConfig.NetworkType) throws -> String {
        let zcashNetwork = network == .mainnet
            ? ZcashNetworkBuilder.network(for: .mainnet)
            : ZcashNetworkBuilder.network(for: .testnet)
        let derivationTool = DerivationTool(networkType: zcashNetwork.networkType)
        let accountIndex = Zip32AccountIndex(account)
        let usk = try derivationTool.deriveUnifiedSpendingKey(seed: seed.bytes, accountIndex: accountIndex)
        let ufvk = try derivationTool.deriveUnifiedFullViewingKey(from: usk)
        return ufvk.stringEncoded
    }
}
