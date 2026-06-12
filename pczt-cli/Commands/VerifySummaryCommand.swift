//
//  VerifySummaryCommand.swift
//  pczt-cli
//
//  Run the watch's display==signed verification (pczt_summary) against a PCZT.
//  Mirrors `ZecSigningHandler.verifyPcztSummary` on iOS / `verifyRequestSummary`
//  on Android: parse the PCZT, match the approved recipient's receiver bytes
//  against the outputs, and confirm the PCZT-derived amount/fee equal what the
//  user approved. Point it at a *redacted* PCZT (propose --redact) to test the
//  exact bytes the watch sees.
//

import ArgumentParser
import Foundation
import ZcashSignerCore

struct VerifySummaryCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "verify-summary",
        abstract: "Run the watch's pczt_summary display==signed check on a PCZT"
    )

    @Argument(help: "PCZT file path (use the redacted PCZT for a faithful watch check)")
    var pcztFile: String

    @Option(name: .long, help: "Recipient address the user approved (UA / Sapling / transparent)")
    var recipient: String

    @Option(name: .long, help: "Network: mainnet or testnet")
    var network: String = "mainnet"

    @Option(name: .long, help: "Assert the PCZT-derived recipient amount equals this (zatoshi)")
    var expectAmount: UInt64?

    @Option(name: .long, help: "Assert the PCZT-derived fee equals this (zatoshi)")
    var expectFee: UInt64?

    mutating func run() async throws {
        let pczt = try StateManager.shared.loadPCZT(path: pcztFile)
        let mainnet = network.lowercased() != "testnet"
        errorOutput("[VerifySummary] PCZT \(pczt.count) bytes — recipient \(recipient) — \(mainnet ? "mainnet" : "testnet")")

        let summary = try pcztSummary(pcztData: pczt, recipientAddress: recipient, mainnet: mainnet)

        print("PCZT Summary (watch verification):")
        print("  recipient_amount_zatoshis:       \(summary.recipientAmountZatoshis)")
        print("  fee_zatoshis:                    \(summary.feeZatoshis)")
        print("  matched_outputs:                 \(summary.matchedOutputs)")
        print("  outputs (t/s/o):                 \(summary.transparentOutputs)/\(summary.saplingOutputs)/\(summary.orchardOutputs)")
        print("  has_unverified_recipient_amount: \(summary.hasUnverifiedRecipientAmount)")

        // Mirror the watch's fail-closed guards (ZecSigningHandler.verifyPcztSummary).
        var failures: [String] = []
        if summary.hasUnverifiedRecipientAmount {
            failures.append(
                "recipient amount NOT verifiable from the PCZT — receiver bytes didn't match "
                + "(this is exactly the failure mode if redactPCZTForSigner strips output recipient/value). The watch would REJECT."
            )
        }
        if summary.matchedOutputs == 0 {
            failures.append("no PCZT output matches the approved recipient — the watch would REJECT.")
        }
        if let expect = expectAmount, summary.recipientAmountZatoshis != expect {
            failures.append("amount mismatch: PCZT=\(summary.recipientAmountZatoshis) approved=\(expect)")
        }
        if let expect = expectFee, summary.feeZatoshis != expect {
            failures.append("fee mismatch: PCZT=\(summary.feeZatoshis) approved=\(expect)")
        }

        if failures.isEmpty {
            print("VERIFIED ✓ — the watch would approve this PCZT for the shown recipient and amount.")
        } else {
            for failure in failures { errorOutput("FAIL: \(failure)") }
            throw ExitCode.failure
        }
    }
}
