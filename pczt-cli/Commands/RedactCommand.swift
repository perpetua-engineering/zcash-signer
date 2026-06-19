//
//  RedactCommand.swift
//  pczt-cli
//
//  Redact a full PCZT to the exact bytes sent to the watch signer.
//

import ArgumentParser
import Foundation

struct RedactCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "redact",
        abstract: "Redact a full PCZT for the external signer"
    )

    @Argument(help: "Full PCZT file path")
    var pcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[Redact] Loading full PCZT from \(pcztFile)...")
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)
        errorOutput("[Redact] Full PCZT size: \(pczt.count) bytes")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let redacted = try await wallet.redactForSigner(pczt)
        await wallet.stop()

        let redactedId = StateManager.shared.generatePCZTId() + "_redacted"
        let savedPath = try StateManager.shared.savePCZT(redacted, id: redactedId)

        errorOutput("[Redact] Saved redacted PCZT to \(savedPath.path)")
        errorOutput("[Redact] Redacted PCZT size: \(pczt.count) -> \(redacted.count) bytes")

        let output = CreatePCZTOutput(
            pcztFile: savedPath.path,
            pcztId: redactedId,
            size: redacted.count
        )
        try outputJSON(output)
    }

    private func resolveConfig() throws -> WalletConfig {
        guard StateManager.shared.walletConfigExists() else {
            throw ValidationError("No saved wallet config found. Run 'init' first.")
        }
        var config = try StateManager.shared.loadWalletConfig()
        if let lightwalletd = lightwalletd {
            config = WalletConfig(
                ufvk: config.ufvk,
                network: config.network,
                birthday: config.birthday,
                lightwalletdURL: lightwalletd,
                accountIndex: config.accountIndex,
                transparentAddress: config.transparentAddress
            )
        }
        return config
    }
}
