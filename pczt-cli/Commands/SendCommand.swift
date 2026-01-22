//
//  SendCommand.swift
//  pczt-cli
//
//  Complete and broadcast a signed PCZT using the sequential flow.
//  This adds proofs to the signed PCZT, then extracts and broadcasts.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct SendCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "send",
        abstract: "Complete and broadcast a signed PCZT (sequential flow)"
    )

    @Argument(help: "Signed PCZT file path (signatures applied, no proofs)")
    var signedPcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[Send] Loading signed PCZT from \(signedPcztFile)...")
        let signedPczt = try StateManager.shared.loadPCZT(path: signedPcztFile)
        errorOutput("[Send] Signed PCZT size: \(signedPczt.count) bytes")

        errorOutput("[Send] Adding proofs and broadcasting (sequential flow)...")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        let txid = try await wallet.sendFromSignedPCZT(signedPczt)

        await wallet.stop()

        errorOutput("[Send] Transaction submitted successfully!")
        errorOutput("[Send] TxID: \(txid)")

        let output = BroadcastOutput(
            txid: txid,
            success: true
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
