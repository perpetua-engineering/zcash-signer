//
//  InspectCommand.swift
//  pczt-cli
//
//  Inspect a PCZT to see its contents and state.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct InspectCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Inspect a PCZT to see its contents"
    )

    @Argument(help: "PCZT file path")
    var pcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[Inspect] Loading PCZT from \(pcztFile)...")
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)
        errorOutput("[Inspect] PCZT size: \(pczt.count) bytes")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let summary = try await wallet.pcztSummary(pczt)
        await wallet.stop()

        // Output the summary
        print(summary)
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
