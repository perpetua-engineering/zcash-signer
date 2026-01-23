//
//  main.swift
//  pczt-cli
//
//  CLI tool that mimics the phone+watch wallet PCZT flow with separate invocations for each step.
//

import ArgumentParser
import Foundation

struct PCZTCli: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pczt-cli",
        abstract: "CLI tool for Zcash PCZT workflow (phone+watch simulation)",
        version: "0.1.0",
        subcommands: [
            InitCommand.self,
            SyncCommand.self,
            AddressCommand.self,
            ProposeCommand.self,
            ExtractSighashesCommand.self,
            SignCommand.self,
            ApplySignaturesCommand.self,
            ProveCommand.self,
            BroadcastCommand.self,
            SendCommand.self,
            InspectCommand.self,
            TestUfvkCommand.self,
        ]
    )
}

// Entry point that runs the async command
let semaphore = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0

Task {
    do {
        var command = try PCZTCli.parseAsRoot()
        if var asyncCommand = command as? AsyncParsableCommand {
            try await asyncCommand.run()
        } else {
            try command.run()
        }
    } catch {
        PCZTCli.exit(withError: error)
    }
    semaphore.signal()
}

semaphore.wait()
Foundation.exit(exitCode)
