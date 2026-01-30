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

        // === Find first valid diversifier index using FF1-AES256 ===
        let (diversifierIndex, diversifier) = try deriveFirstValidDiversifierIndex(
            seed: seed,
            coinType: isMainnet ? ZSIG_MAINNET_COIN_TYPE : 1,
            account: account
        )
        errorOutput("[Compare] First valid diversifier index: \(diversifierIndex)")
        errorOutput("[Compare] Diversifier: \(diversifier.hexString)")

        // === Method 1: Our Rust library (using first valid diversifier index) ===
        let rustTransparentAddress = try deriveTransparentAddress(
            seed: seed,
            account: account,
            index: UInt32(diversifierIndex),
            mainnet: isMainnet
        )
        errorOutput("[Compare] Rust BIP-44 index \(diversifierIndex): \(rustTransparentAddress)")

        // For comparison, also show index 0 address
        let rustIndex0Address = try deriveTransparentAddress(
            seed: seed,
            account: account,
            index: 0,
            mainnet: isMainnet
        )
        if diversifierIndex != 0 {
            errorOutput("[Compare] Rust BIP-44 index 0 (for reference): \(rustIndex0Address)")
        }

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
            diversifierIndex: diversifierIndex,
            unifiedAddress: unifiedAddress.stringEncoded,
            note: match
                ? "Addresses match! FF1-AES256 diversifier derivation working correctly"
                : "Addresses differ - possible bug in FF1-AES256 or DiversifyHash implementation"
        )
        try outputJSON(output)

        // Also print a clear summary to stderr
        if match {
            errorOutput("[Compare] MATCH - Both methods produce the same address")
        } else {
            errorOutput("[Compare] MISMATCH - Addresses differ!")
            errorOutput("[Compare] Debug: Check FF1-AES256 implementation or DiversifyHash")
        }
    }
}

struct CompareAddressOutput: Codable {
    let rustAddress: String
    let sdkAddress: String
    let match: Bool
    let diversifierIndex: UInt64
    let unifiedAddress: String
    let note: String
}
