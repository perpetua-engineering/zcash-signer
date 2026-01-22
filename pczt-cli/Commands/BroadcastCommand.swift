//
//  BroadcastCommand.swift
//  pczt-cli
//
//  Submit proven+signed PCZT to network.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

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

    @Flag(name: .long, help: "On failure, compare PCZT summaries and extracted sighashes")
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
                await diagnoseMismatch(provenPczt: provenPczt, signedPczt: signedPczt, wallet: wallet)
            }
            await wallet.stop()
            throw error
        }
    }

    private func diagnoseMismatch(
        provenPczt: Data,
        signedPczt: Data,
        wallet: WalletManager
    ) async {
        errorOutput("[Broadcast][Diagnose] Comparing PCZT summaries...")
        do {
            let provenSummary = try await wallet.pcztSummary(provenPczt)
            let signedSummary = try await wallet.pcztSummary(signedPczt)
            errorOutput("[Broadcast][Diagnose] Proven summary: \(provenSummary)")
            errorOutput("[Broadcast][Diagnose] Signed summary: \(signedSummary)")
        } catch {
            errorOutput("[Broadcast][Diagnose] Failed to get PCZT summaries: \(error)")
        }

        errorOutput("[Broadcast][Diagnose] Comparing extracted sighashes...")
        do {
            let provenSighashes = try await wallet.extractSighashes(from: provenPczt)
            let signedSighashes = try await wallet.extractSighashes(from: signedPczt)

            let sameShielded = provenSighashes.shieldedSighash == signedSighashes.shieldedSighash
            errorOutput("[Broadcast][Diagnose] Shielded sighash match: \(sameShielded)")
            errorOutput("[Broadcast][Diagnose] Proven shielded sighash: \(provenSighashes.shieldedSighash.hexString)")
            errorOutput("[Broadcast][Diagnose] Signed shielded sighash: \(signedSighashes.shieldedSighash.hexString)")

            let provenOrchard = provenSighashes.orchardSpends.map { ($0.index, $0.randomizer.hexString) }
            let signedOrchard = signedSighashes.orchardSpends.map { ($0.index, $0.randomizer.hexString) }
            errorOutput("[Broadcast][Diagnose] Orchard randomizers (proven): \(provenOrchard)")
            errorOutput("[Broadcast][Diagnose] Orchard randomizers (signed): \(signedOrchard)")

            let provenTransparent = provenSighashes.transparentInputs.map { ($0.index, $0.sighash.hexString) }
            let signedTransparent = signedSighashes.transparentInputs.map { ($0.index, $0.sighash.hexString) }
            errorOutput("[Broadcast][Diagnose] Transparent sighashes (proven): \(provenTransparent)")
            errorOutput("[Broadcast][Diagnose] Transparent sighashes (signed): \(signedTransparent)")
        } catch {
            errorOutput("[Broadcast][Diagnose] Failed to extract sighashes: \(error)")
        }

        errorOutput("[Broadcast][Diagnose] Attempting local extract variants (no broadcast)...")
        do {
            let txid = try await wallet.debugExtractTxFromPCZT(
                pcztWithProofs: provenPczt,
                pcztWithSigs: signedPczt
            )
            errorOutput("[Broadcast][Diagnose] Extract from split PCZTs succeeded: \(txid)")
        } catch {
            errorOutput("[Broadcast][Diagnose] Extract from split PCZTs failed: \(error)")
        }

        do {
            let pcztWithProofsFromSigned = try await wallet.addProofs(to: signedPczt)
            let txid = try await wallet.debugExtractTxFromSignedAndProvenPCZT(pcztWithProofsFromSigned)
            errorOutput("[Broadcast][Diagnose] Extract from sequential (signed→prove) PCZT succeeded: \(txid)")
        } catch {
            errorOutput("[Broadcast][Diagnose] Extract from sequential (signed→prove) PCZT failed: \(error)")
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
                    accountIndex: config.accountIndex
                )
            }
            return config
        } else {
            throw ValidationError("No saved wallet config found. Run 'init' first.")
        }
    }
}
