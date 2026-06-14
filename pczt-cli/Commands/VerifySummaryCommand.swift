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

    @Option(name: .long, help: "Approved memo to bind against the recipient note (empty == no memo)")
    var memo: String = ""

    @Flag(name: .long, help: "Treat this as a shielding self-send (recipient must be wallet-owned, ZEC-4)")
    var shielding: Bool = false

    @Flag(name: .long, help: "Skip the CR-1337 viewing-key ownership/memo verification even if ZCASH_SEED is set")
    var skipOwnership: Bool = false

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

        // CR-1337: viewing-key ownership totality + memo binding. This is the
        // arm `pczt_summary` cannot do — it needs the wallet's viewing keys to
        // prove every non-recipient output (change/own-receiver/shielding dest)
        // belongs to the wallet, and to recover + bind the recipient memo. The
        // watch runs this from the SE seed; here we derive keys from ZCASH_SEED
        // so the funded-wallet roundtrip exercises the exact same check.
        let coinType: UInt32 = mainnet ? 133 : 1
        if !skipOwnership, let seed = try? SeedManager.parseSeed() {
            let expectedAmount = expectAmount ?? summary.recipientAmountZatoshis
            let verdict = try pcztVerify(
                seed: seed,
                pcztData: pczt,
                recipientAddress: recipient,
                expectedAmount: expectedAmount,
                memo: memo,
                coinType: coinType,
                account: 0,
                mainnet: mainnet
            )
            print("PCZT Ownership Totality (CR-1337):")
            print("  recipient_output_count:          \(verdict.recipientOutputCount)")
            print("  foreign_output_count:            \(verdict.foreignOutputCount)")
            print("  all_outputs_accounted:           \(verdict.allOutputsAccounted)")
            print("  recipient_amount_zatoshis:       \(verdict.recipientAmountZatoshis)")
            print("  memo_checked / memo_matches:     \(verdict.memoChecked) / \(verdict.memoMatches)")
            print("  recipient_owned:                 \(verdict.recipientOwned)")

            if verdict.foreignOutputCount > 0 || !verdict.allOutputsAccounted {
                failures.append(
                    "totality FAILED: \(verdict.foreignOutputCount) output(s) are neither the "
                    + "recipient nor wallet-owned — a diverted change/own-receiver output. The watch would REJECT."
                )
            }
            if verdict.recipientOutputCount == 0 {
                failures.append("totality decode found no recipient output — the watch would REJECT.")
            }
            if !memo.isEmpty, !(verdict.memoChecked && verdict.memoMatches) {
                failures.append("memo display!=signed: approved memo not bound to the recipient note. The watch would REJECT.")
            }
            if shielding, !verdict.recipientOwned {
                failures.append("ZEC-4: shielding destination is NOT wallet-owned — the watch would REJECT.")
            }
        } else if !skipOwnership {
            errorOutput("[VerifySummary] ZCASH_SEED not set — skipping CR-1337 ownership/memo verification (summary-only check).")
        }

        if failures.isEmpty {
            print("VERIFIED ✓ — the watch would approve this PCZT for the shown recipient and amount.")
        } else {
            for failure in failures { errorOutput("FAIL: \(failure)") }
            throw ExitCode.failure
        }
    }
}
