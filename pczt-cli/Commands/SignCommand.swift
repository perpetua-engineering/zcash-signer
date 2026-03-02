//
//  SignCommand.swift
//  pczt-cli
//
//  Sign a PCZT binary using the full Signer role (same path as the watch app).
//  Requires ZCASH_SEED environment variable.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit
import ZcashSignerCore
import ZcashSigner

struct SignCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sign",
        abstract: "Sign a PCZT binary (watch simulation)"
    )

    @Argument(help: "PCZT file path (binary)")
    var pcztFile: String

    @Option(name: .long, help: "Account index for key derivation")
    var account: UInt32 = 0

    @Flag(name: .long, help: "Use testnet coin type for derivation")
    var testnet: Bool = false

    mutating func run() async throws {
        errorOutput("[Sign] Loading PCZT from \(pcztFile)...")

        let pcztData = try StateManager.shared.loadPCZT(path: pcztFile)
        errorOutput("[Sign] PCZT size: \(pcztData.count) bytes")

        // Show PCZT summary
        let info = try pcztInfo(pcztData: pcztData)
        errorOutput("[Sign] PCZT contents:")
        errorOutput("[Sign]   Orchard actions: \(info.orchardActions)")
        errorOutput("[Sign]   Sapling spends: \(info.saplingSpends)")
        errorOutput("[Sign]   Transparent inputs: \(info.transparentInputs)")
        errorOutput("[Sign]   Transparent outputs: \(info.transparentOutputs)")

        // Derive keys from seed
        let seed = try SeedManager.parseSeed()
        let signer = try LocalSigner(
            seed: seed,
            account: account,
            mainnet: !testnet
        )

        errorOutput("[Sign] Signing with derived keys (account \(account))...")

        let signedPczt = try signer.sign(pcztData: pcztData)

        // Save signed PCZT
        let signedId = StateManager.shared.generatePCZTId() + "_signed"
        let savedPath = try StateManager.shared.savePCZT(signedPczt, id: signedId)

        errorOutput("[Sign] Saved signed PCZT to \(savedPath.path)")
        errorOutput("[Sign] Signed PCZT size: \(signedPczt.count) bytes")

        let output = SignOutput(
            pcztFile: savedPath.path,
            size: signedPczt.count
        )
        try outputJSON(output)
    }
}

// MARK: - Output Types

struct SignOutput: Codable {
    let pcztFile: String
    let size: Int
}
