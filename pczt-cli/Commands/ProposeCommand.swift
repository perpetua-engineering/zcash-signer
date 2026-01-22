//
//  ProposeCommand.swift
//  pczt-cli
//
//  Create shielding or transfer proposals and immediately convert to PCZT.
//  Since Proposal objects are internal to the SDK, we combine propose + create-pczt.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct ProposeCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "propose",
        abstract: "Create a transaction proposal and PCZT",
        subcommands: [ShieldSubcommand.self, TransferSubcommand.self]
    )
}

// MARK: - Shield Subcommand

struct ShieldSubcommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "shield",
        abstract: "Create a shielding proposal and PCZT"
    )

    @Argument(help: "Shielding threshold in zatoshi")
    var threshold: UInt64

    @Option(name: .long, help: "UFVK (uses saved config if not provided)")
    var ufvk: String?

    @Option(name: .long, help: "Memo for shielded output")
    var memo: String?

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

        errorOutput("[Propose] Creating shielding proposal...")
        errorOutput("[Propose] Threshold: \(threshold) zatoshi")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        // Quick sync to get current state
        try await wallet.sync(timeoutSeconds: 300)

        let memoObj = try memo.map { try Memo(string: $0) }
        let proposal = try await wallet.proposeShielding(
            threshold: Zatoshi(Int64(threshold)),
            memo: memoObj
        )

        // Immediately create PCZT from proposal
        errorOutput("[Propose] Creating PCZT from proposal...")
        let pczt = try await wallet.createPCZT(from: proposal)

        await wallet.stop()

        // Save PCZT
        let pcztId = StateManager.shared.generatePCZTId()
        let savedPath = try StateManager.shared.savePCZT(pczt, id: pcztId)

        errorOutput("[Propose] Saved PCZT to \(savedPath.path)")

        let output = CreatePCZTOutput(
            pcztFile: savedPath.path,
            pcztId: pcztId,
            size: pczt.count
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
            return try StateManager.shared.loadWalletConfig()
        } else {
            throw ValidationError("No UFVK provided and no saved wallet config found. Run 'init' first.")
        }
    }
}

// MARK: - Transfer Subcommand

struct TransferSubcommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "transfer",
        abstract: "Create a transfer proposal and PCZT"
    )

    @Argument(help: "Recipient address")
    var recipient: String

    @Argument(help: "Amount in zatoshi")
    var amount: UInt64

    @Option(name: .long, help: "UFVK (uses saved config if not provided)")
    var ufvk: String?

    @Option(name: .long, help: "Memo for shielded output")
    var memo: String?

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

        errorOutput("[Propose] Creating transfer proposal...")
        errorOutput("[Propose] Recipient: \(recipient)")
        errorOutput("[Propose] Amount: \(amount) zatoshi")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        try await wallet.sync(timeoutSeconds: 300)

        let memoObj = try memo.map { try Memo(string: $0) }
        let proposal = try await wallet.proposeTransfer(
            to: recipient,
            amount: Zatoshi(Int64(amount)),
            memo: memoObj
        )

        // Immediately create PCZT from proposal
        errorOutput("[Propose] Creating PCZT from proposal...")
        let pczt = try await wallet.createPCZT(from: proposal)

        await wallet.stop()

        // Save PCZT
        let pcztId = StateManager.shared.generatePCZTId()
        let savedPath = try StateManager.shared.savePCZT(pczt, id: pcztId)

        errorOutput("[Propose] Saved PCZT to \(savedPath.path)")

        let output = CreatePCZTOutput(
            pcztFile: savedPath.path,
            pcztId: pcztId,
            size: pczt.count
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
            return try StateManager.shared.loadWalletConfig()
        } else {
            throw ValidationError("No UFVK provided and no saved wallet config found. Run 'init' first.")
        }
    }
}
