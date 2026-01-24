//
//  TestUfvkCommand.swift
//  pczt-cli
//
//  Test UFVK derivation: compare Rust library output against SDK
//

import ArgumentParser
import Foundation
import ZcashSignerCore
import ZcashLightClientKit

struct TestUfvkCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "test-ufvk",
        abstract: "Test UFVK derivation by comparing Rust library against SDK"
    )

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String = "mainnet"

    @Option(name: .long, help: "Account index")
    var account: UInt32 = 0

    mutating func run() async throws {
        let networkType = network == "testnet" ? NetworkType.testnet : NetworkType.mainnet
        let coinType: UInt32 = networkType == .mainnet ? ZSIG_MAINNET_COIN_TYPE : 1
        let isMainnet = networkType == .mainnet

        // Parse seed from environment
        let seed = try SeedManager.parseSeed()
        errorOutput("[Test] Parsed seed (\(seed.count) bytes)")

        // 1. Derive UFVK using SDK
        errorOutput("[Test] Deriving UFVK using SDK...")
        let sdkUFVK = try deriveUFVKWithSDK(seed: seed, account: account, network: networkType)
        errorOutput("[Test] SDK UFVK: \(sdkUFVK)")
        errorOutput("[Test] SDK UFVK length: \(sdkUFVK.count)")

        // 2. Derive UFVK using Rust library (Combined: Transparent + Sapling + Orchard)
        errorOutput("[Test] Deriving UFVK using Rust library...")
        let rustUFVK = try deriveCombinedUFVKString(
            seed: seed,
            coinType: coinType,
            account: account,
            mainnet: isMainnet
        )
        errorOutput("[Test] Rust UFVK: \(rustUFVK)")
        errorOutput("[Test] Rust UFVK length: \(rustUFVK.count)")

        // 3. Validate the Rust UFVK with SDK's parser
        errorOutput("[Test] Validating Rust UFVK with SDK...")
        do {
            let zcashNetwork = isMainnet
                ? ZcashNetworkBuilder.network(for: .mainnet)
                : ZcashNetworkBuilder.network(for: .testnet)

            let derivationTool = DerivationTool(networkType: zcashNetwork.networkType)

            // First check if valid
            let isValid = derivationTool.isValidUnifiedFullViewingKey(rustUFVK)
            errorOutput("[Test] isValidUnifiedFullViewingKey: \(isValid)")

            if isValid {
                // Try to derive an address from it
                let address = try derivationTool.deriveUnifiedAddressFrom(ufvk: rustUFVK)
                errorOutput("[Test] Derived UA from Rust UFVK: \(address.stringEncoded)")
                errorOutput("[Test] SUCCESS: Rust UFVK validated by SDK!")
            } else {
                errorOutput("[Test] FAILED: Rust UFVK is not valid according to SDK")
            }
        } catch {
            errorOutput("[Test] FAILED to validate Rust UFVK: \(error)")
        }

        // 4. Compare
        if sdkUFVK == rustUFVK {
            errorOutput("[Test] PERFECT MATCH: SDK and Rust UFVKs are identical!")
        } else {
            errorOutput("[Test] MISMATCH: UFVKs differ")
            errorOutput("[Test] This may be expected if receiver order or padding differs")
        }

        // Output JSON result
        let output: [String: Any] = [
            "sdk_ufvk": sdkUFVK,
            "rust_ufvk": rustUFVK,
            "sdk_length": sdkUFVK.count,
            "rust_length": rustUFVK.count,
            "match": sdkUFVK == rustUFVK
        ]

        if let jsonData = try? JSONSerialization.data(withJSONObject: output, options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            print(jsonString)
        }
    }

    private func deriveUFVKWithSDK(seed: Data, account: UInt32, network: NetworkType) throws -> String {
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
