//
//  ExtractSighashesCommand.swift
//  pczt-cli
//
//  Extract signing data from PCZT.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct ExtractSighashesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "extract-sighashes",
        abstract: "Extract signing data from PCZT"
    )

    @Argument(help: "PCZT file path")
    var pcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String?

    @Option(name: .long, help: "Wallet birthday height")
    var birthday: UInt32?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[ExtractSighashes] Loading PCZT from \(pcztFile)...")

        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)

        errorOutput("[ExtractSighashes] PCZT size: \(pczt.count) bytes")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let sighashes = try await wallet.extractSighashes(from: pczt)

        await wallet.stop()

        errorOutput("[ExtractSighashes] Extracted sighashes:")
        errorOutput("[ExtractSighashes]   Orchard spends: \(sighashes.orchardSpends.count)")
        errorOutput("[ExtractSighashes]   Sapling spends: \(sighashes.saplingSpends.count)")
        errorOutput("[ExtractSighashes]   Transparent inputs: \(sighashes.transparentInputs.count)")

        let output = SighashesOutput(
            shieldedSighash: sighashes.shieldedSighash.hexString,
            orchardSpends: sighashes.orchardSpends.map {
                OrchardSpendOutput(index: $0.index, randomizer: $0.randomizer.hexString)
            },
            saplingSpends: sighashes.saplingSpends.map {
                SaplingSpendOutput(index: $0.index, randomizer: $0.randomizer.hexString)
            },
            transparentInputs: sighashes.transparentInputs.map {
                TransparentInputOutput(
                    index: $0.index,
                    sighash: $0.sighash.hexString,
                    sighashType: $0.sighashType,
                    derivationPath: $0.derivationPath,
                    scriptPubKey: $0.scriptPubKey.hexString,
                    value: UInt64($0.value.amount)
                )
            }
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
