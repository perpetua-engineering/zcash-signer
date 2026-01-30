//
//  InitCommand.swift
//  pczt-cli
//
//  Derive keys from seed - outputs UFVK (for phone) and ASK (for watch).
//

import ArgumentParser
import Foundation
import ZcashSignerCore
import ZcashLightClientKit

struct InitCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Derive keys from seed (ZCASH_SEED env var)"
    )

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String = "mainnet"

    @Option(name: .long, help: "Account index")
    var account: UInt32 = 0

    @Option(name: .long, help: "Wallet birthday height")
    var birthday: UInt32 = 2657762  // Recent mainnet height

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String = "https://zec.rocks:443"

    mutating func run() async throws {
        let networkType = network == "testnet" ? NetworkType.testnet : NetworkType.mainnet
        let coinType: UInt32 = networkType == .mainnet ? ZSIG_MAINNET_COIN_TYPE : 1

        // Parse seed from environment
        let seed = try SeedManager.parseSeed()
        errorOutput("[Init] Parsed seed (\(seed.count) bytes)")

        // Derive Orchard spending key and ASK
        let spendingKey = try ZcashOrchardSpendingKey.deriveFromSeed(
            seed,
            coinType: coinType,
            account: account
        )
        let ask = try spendingKey.deriveAsk()
        errorOutput("[Init] Derived Orchard ASK")

        // Find first valid diversifier index (required for ZIP-316 UA compatibility)
        let (diversifierIndex, _) = try deriveFirstValidDiversifierIndex(
            seed: seed,
            coinType: coinType,
            account: account
        )
        errorOutput("[Init] First valid diversifier index: \(diversifierIndex)")

        // Derive transparent address using the diversifier index
        // This ensures the t-address matches what's in the Unified Address
        let transparentAddress = try deriveTransparentAddress(
            seed: seed,
            account: account,
            index: UInt32(diversifierIndex),
            mainnet: networkType == .mainnet
        )
        errorOutput("[Init] Derived transparent address: \(transparentAddress)")

        // Derive UFVK using SDK
        let ufvk = try deriveUFVK(seed: seed, account: account, network: networkType)
        errorOutput("[Init] Derived UFVK")

        // Save wallet config
        let config = WalletConfig(
            ufvk: ufvk,
            network: networkType == .mainnet ? .mainnet : .testnet,
            birthday: birthday,
            lightwalletdURL: lightwalletd,
            accountIndex: account,
            transparentAddress: transparentAddress
        )
        try StateManager.shared.saveWalletConfig(config)
        errorOutput("[Init] Saved wallet config to \(StateManager.shared.walletConfigFile.path)")

        // Output
        let output = InitOutput(
            ufvk: ufvk,
            ask: ask.bytes.hexString,
            network: network,
            birthday: birthday,
            transparentAddress: transparentAddress
        )
        try outputJSON(output)
    }

    private func deriveUFVK(seed: Data, account: UInt32, network: NetworkType) throws -> String {
        // Use the SDK to derive UFVK from seed
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

extension Data {
    var bytes: [UInt8] {
        Array(self)
    }
}
