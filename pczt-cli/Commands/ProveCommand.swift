//
//  ProveCommand.swift
//  pczt-cli
//
//  Add zk-SNARK proofs to PCZT.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct ProveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "prove",
        abstract: "Add zk-SNARK proofs to PCZT"
    )

    @Argument(help: "PCZT file path")
    var pcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[Prove] Loading PCZT from \(pcztFile)...")
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)
        errorOutput("[Prove] PCZT size: \(pczt.count) bytes")

        errorOutput("[Prove] Adding proofs (this may take a while)...")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let provenPczt = try await wallet.addProofs(to: pczt)

        await wallet.stop()

        // Save proven PCZT
        let provenId = StateManager.shared.generatePCZTId() + "_proven"
        let savedPath = try StateManager.shared.savePCZT(provenPczt, id: provenId)

        errorOutput("[Prove] Saved proven PCZT to \(savedPath.path)")
        errorOutput("[Prove] Size increased: \(pczt.count) -> \(provenPczt.count) bytes")

        let output = ProveOutput(
            pcztFile: savedPath.path,
            size: provenPczt.count
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
                    accountIndex: config.accountIndex,
                    transparentAddress: config.transparentAddress
                )
            }
            return config
        } else {
            throw ValidationError("No saved wallet config found. Run 'init' first.")
        }
    }
}
