//
//  InspectCommand.swift
//  pczt-cli
//
//  Inspect a PCZT to see its contents and state.
//

import ArgumentParser
import Foundation
import ZcashSignerCore

struct InspectCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Inspect a PCZT to see its contents"
    )

    @Argument(help: "PCZT file path")
    var pcztFile: String

    mutating func run() async throws {
        errorOutput("[Inspect] Loading PCZT from \(pcztFile)...")
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)
        errorOutput("[Inspect] PCZT size: \(pczt.count) bytes")

        let info = try pcztInfo(pcztData: pczt)

        print("PCZT Summary:")
        print("  Orchard actions:     \(info.orchardActions)")
        print("  Sapling spends:      \(info.saplingSpends)")
        print("  Transparent inputs:  \(info.transparentInputs)")
        print("  Transparent outputs: \(info.transparentOutputs)")
    }
}
