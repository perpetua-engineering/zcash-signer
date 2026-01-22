//
//  ApplySignaturesCommand.swift
//  pczt-cli
//
//  Apply signatures to PCZT.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct ApplySignaturesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "apply-signatures",
        abstract: "Apply signatures to PCZT"
    )

    @Argument(help: "PCZT file path")
    var pcztFile: String

    @Argument(help: "Signatures JSON file path")
    var signaturesFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[ApplySignatures] Loading PCZT from \(pcztFile)...")
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)

        errorOutput("[ApplySignatures] Loading signatures from \(signaturesFile)...")
        let signaturesData = try Data(contentsOf: URL(fileURLWithPath: signaturesFile))
        let signaturesInput = try JSON.decode(SignaturesInput.self, from: signaturesData)

        // Convert to SDK types
        let orchardSigs = try signaturesInput.orchardSignatures.map { sig -> ShieldedSignature in
            guard let signature = Data(hex: sig.signature) else {
                throw ValidationError("Invalid signature hex at index \(sig.index)")
            }
            return ShieldedSignature(index: sig.index, signature: signature)
        }

        let saplingSigs = try signaturesInput.saplingSignatures.map { sig -> ShieldedSignature in
            guard let signature = Data(hex: sig.signature) else {
                throw ValidationError("Invalid signature hex at index \(sig.index)")
            }
            return ShieldedSignature(index: sig.index, signature: signature)
        }

        let transparentSigs = try signaturesInput.transparentSignatures.map { sig -> TransparentSignature in
            guard let signature = Data(hex: sig.signature),
                  let publicKey = Data(hex: sig.publicKey) else {
                throw ValidationError("Invalid signature or public key hex at index \(sig.index)")
            }
            return TransparentSignature(
                index: sig.index,
                signature: signature,
                publicKey: publicKey,
                sighashType: sig.sighashType
            )
        }

        let signatures = PCZTSignatures(
            orchardSignatures: orchardSigs,
            saplingSignatures: saplingSigs,
            transparentSignatures: transparentSigs
        )

        errorOutput("[ApplySignatures] Applying signatures...")
        errorOutput("[ApplySignatures]   Orchard: \(orchardSigs.count)")
        errorOutput("[ApplySignatures]   Sapling: \(saplingSigs.count)")
        errorOutput("[ApplySignatures]   Transparent: \(transparentSigs.count)")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let signedPczt = try await wallet.applySignatures(to: pczt, signatures: signatures)

        await wallet.stop()

        // Save signed PCZT
        let signedId = StateManager.shared.generatePCZTId() + "_signed"
        let savedPath = try StateManager.shared.savePCZT(signedPczt, id: signedId)

        errorOutput("[ApplySignatures] Saved signed PCZT to \(savedPath.path)")

        let output = ApplySignaturesOutput(
            pcztFile: savedPath.path,
            size: signedPczt.count
        )
        try outputJSON(output)
    }

    private func resolveConfig() throws -> WalletConfig {
        if StateManager.shared.walletConfigExists() {
            var config = try StateManager.shared.loadWalletConfig()
            if let lightwalletd = lightwalletd {
                config = WalletConfig(
                    ufvk: config.ufvk,
                    network: config.network,
                    birthday: config.birthday,
                    lightwalletdURL: lightwalletd,
                    accountIndex: config.accountIndex
                )
            }
            return config
        } else {
            throw ValidationError("No saved wallet config found. Run 'init' first.")
        }
    }
}
