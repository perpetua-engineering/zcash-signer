//
//  SyncCommand.swift
//  pczt-cli
//
//  Sync wallet with lightwalletd and display balance.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct SyncCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sync",
        abstract: "Sync wallet with lightwalletd"
    )

    @Argument(help: "UFVK (or use saved config)")
    var ufvk: String?

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String?

    @Option(name: .long, help: "Wallet birthday height")
    var birthday: UInt32?

    @Option(name: .long, help: "Sync timeout in seconds")
    var timeout: Int = 3600

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        // Load config or use arguments
        let config = try resolveConfig()

        errorOutput("[Sync] Starting sync...")
        errorOutput("[Sync] UFVK: \(config.ufvk.prefix(20))...")
        errorOutput("[Sync] Network: \(config.network.rawValue)")
        errorOutput("[Sync] Lightwalletd: \(config.lightwalletdURL)")
        errorOutput("[Sync] Birthday: \(config.birthday)")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        try await wallet.sync(timeoutSeconds: timeout)

        let balances = await wallet.getBalances()
        let height = await wallet.getLatestBlockHeight()

        await wallet.stop()

        let output = SyncOutput(
            synced: true,
            latestBlockHeight: UInt64(height),
            totalBalance: UInt64(balances.total.amount),
            spendableBalance: UInt64(balances.spendable.amount),
            transparentBalance: UInt64(balances.transparent.amount)
        )
        try outputJSON(output)
    }

    private func resolveConfig() throws -> WalletConfig {
        if let ufvk = ufvk {
            let networkType: WalletConfig.NetworkType = network == "testnet" ? .testnet : .mainnet
            return WalletConfig(
                ufvk: ufvk,
                network: networkType,
                birthday: birthday ?? 2657762,
                lightwalletdURL: lightwalletd ?? "https://zec.rocks:443",
                accountIndex: 0
            )
        } else if StateManager.shared.walletConfigExists() {
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
            throw ValidationError("No UFVK provided and no saved wallet config found. Run 'init' first.")
        }
    }
}
