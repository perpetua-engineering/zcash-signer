//
//  CompareAddressCommand.swift
//  pczt-cli
//
//  Compare transparent address derivation between our Rust library and the SDK.
//  This validates whether our no_std implementation matches the reference.
//

import ArgumentParser
import Foundation
import ZcashSignerCore
import ZcashLightClientKit

struct CompareAddressCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "compare-address",
        abstract: "Compare transparent address derivation: Rust lib vs SDK"
    )

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String = "mainnet"

    @Option(name: .long, help: "Account index")
    var account: UInt32 = 0

    mutating func run() async throws {
        let networkType = network == "testnet" ? NetworkType.testnet : NetworkType.mainnet
        let isMainnet = networkType == .mainnet

        // Parse seed from environment
        let seed = try SeedManager.parseSeed()
        errorOutput("[Compare] Parsed seed (\(seed.count) bytes)")

        // === Method 1: Our Rust library (BIP-44 index 0) ===
        let rustTransparentAddress = try deriveTransparentAddress(
            seed: seed,
            account: account,
            index: 0,
            mainnet: isMainnet
        )
        errorOutput("[Compare] Rust BIP-44 index 0: \(rustTransparentAddress)")

        // === Method 2: SDK - derive UFVK and extract transparent receiver ===
        let zcashNetwork = isMainnet
            ? ZcashNetworkBuilder.network(for: .mainnet)
            : ZcashNetworkBuilder.network(for: .testnet)
        let derivationTool = DerivationTool(networkType: zcashNetwork.networkType)
        let accountIndex = Zip32AccountIndex(account)

        // Derive USK -> UFVK -> UA -> transparent receiver
        let usk = try derivationTool.deriveUnifiedSpendingKey(seed: seed.bytes, accountIndex: accountIndex)
        let ufvk = try derivationTool.deriveUnifiedFullViewingKey(from: usk)
        let unifiedAddress = try derivationTool.deriveUnifiedAddressFrom(ufvk: ufvk.stringEncoded)
        let sdkTransparentAddress = try derivationTool.transparentReceiver(from: unifiedAddress)
        errorOutput("[Compare] SDK UA extraction: \(sdkTransparentAddress.stringEncoded)")

        // === Compare ===
        let match = rustTransparentAddress == sdkTransparentAddress.stringEncoded

        let output = CompareAddressOutput(
            rustAddress: rustTransparentAddress,
            sdkAddress: sdkTransparentAddress.stringEncoded,
            match: match,
            unifiedAddress: unifiedAddress.stringEncoded,
            note: match
                ? "Addresses match - diversifier index 0 is valid for this seed"
                : "Addresses differ - SDK uses a different diversifier index (not 0)"
        )
        try outputJSON(output)

        // Also print a clear summary to stderr
        if match {
            errorOutput("[Compare] ✅ MATCH - Both methods produce the same address")
        } else {
            errorOutput("[Compare] ❌ MISMATCH - Addresses differ!")
            errorOutput("[Compare] This seed's first valid diversifier index is NOT 0")
            errorOutput("[Compare] To match SDK, implement FF1-AES diversifier derivation")
        }
    }
}

struct CompareAddressOutput: Codable {
    let rustAddress: String
    let sdkAddress: String
    let match: Bool
    let unifiedAddress: String
    let note: String
}
