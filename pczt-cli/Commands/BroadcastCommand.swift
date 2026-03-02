//
//  BroadcastCommand.swift
//  pczt-cli
//
//  Submit proven+signed PCZT to network.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit
import ZcashSignerCore

struct BroadcastCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "broadcast",
        abstract: "Submit proven+signed PCZT to network"
    )

    @Argument(help: "Proven PCZT file path")
    var provenPcztFile: String

    @Argument(help: "Signed PCZT file path")
    var signedPcztFile: String

    @Option(name: .long, help: "Lightwalletd server URL")
    var lightwalletd: String?

    @Flag(name: .long, help: "On failure, compare PCZT info between proven and signed")
    var diagnose: Bool = false

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() async throws {
        let config = try resolveConfig()

        errorOutput("[Broadcast] Loading proven PCZT from \(provenPcztFile)...")
        let provenPczt = try StateManager.shared.loadPCZT(path: provenPcztFile)

        errorOutput("[Broadcast] Loading signed PCZT from \(signedPcztFile)...")
        let signedPczt = try StateManager.shared.loadPCZT(path: signedPcztFile)

        errorOutput("[Broadcast] Proven PCZT size: \(provenPczt.count) bytes")
        errorOutput("[Broadcast] Signed PCZT size: \(signedPczt.count) bytes")

        errorOutput("[Broadcast] Creating and submitting transaction...")

        let wallet = try await WalletManager(
            ufvk: config.ufvk,
            birthday: config.birthday,
            lightwalletdURL: config.lightwalletdURL,
            network: config.network == .mainnet ? .mainnet : .testnet,
            verbose: verbose
        )

        do {
            let txid = try await wallet.broadcast(pcztWithProofs: provenPczt, pcztWithSigs: signedPczt)

            errorOutput("[Broadcast] Transaction submitted successfully!")
            errorOutput("[Broadcast] TxID: \(txid)")

            let output = BroadcastOutput(
                txid: txid,
                success: true
            )
            try outputJSON(output)
            await wallet.stop()
        } catch {
            if diagnose {
                diagnoseMismatch(provenPczt: provenPczt, signedPczt: signedPczt)
            }
            await wallet.stop()
            throw error
        }
    }

    private func diagnoseMismatch(provenPczt: Data, signedPczt: Data) {
        errorOutput("[Broadcast][Diagnose] Comparing PCZT info...")
        do {
            let provenInfo = try pcztInfo(pcztData: provenPczt)
            let signedInfo = try pcztInfo(pcztData: signedPczt)
            errorOutput("[Broadcast][Diagnose] Proven:  orchard=\(provenInfo.orchardActions) sapling=\(provenInfo.saplingSpends) transparent_in=\(provenInfo.transparentInputs) transparent_out=\(provenInfo.transparentOutputs)")
            errorOutput("[Broadcast][Diagnose] Signed:  orchard=\(signedInfo.orchardActions) sapling=\(signedInfo.saplingSpends) transparent_in=\(signedInfo.transparentInputs) transparent_out=\(signedInfo.transparentOutputs)")

            let match = provenInfo.orchardActions == signedInfo.orchardActions
                && provenInfo.saplingSpends == signedInfo.saplingSpends
                && provenInfo.transparentInputs == signedInfo.transparentInputs
                && provenInfo.transparentOutputs == signedInfo.transparentOutputs
            errorOutput("[Broadcast][Diagnose] Structure match: \(match)")
        } catch {
            errorOutput("[Broadcast][Diagnose] Failed to parse PCZT info: \(error)")
        }
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
