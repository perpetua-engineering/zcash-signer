//
//  AddressCommand.swift
//  pczt-cli
//
//  Display wallet addresses derived from the UFVK.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit

struct AddressCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "address",
        abstract: "Display wallet receive addresses"
    )

    mutating func run() throws {
        guard StateManager.shared.walletConfigExists() else {
            throw ValidationError("No saved wallet config found. Run 'init' first.")
        }

        let config = try StateManager.shared.loadWalletConfig()
        let networkType: ZcashLightClientKit.NetworkType = config.network == .mainnet ? .mainnet : .testnet
        let derivationTool = DerivationTool(networkType: networkType)

        let unifiedAddress = try derivationTool.deriveUnifiedAddressFrom(ufvk: config.ufvk)
        let transparentAddress = try derivationTool.transparentReceiver(from: unifiedAddress)
        let saplingAddress = try derivationTool.saplingReceiver(from: unifiedAddress)

        let output = AddressOutput(
            unified: unifiedAddress.stringEncoded,
            transparent: transparentAddress.stringEncoded,
            sapling: saplingAddress.stringEncoded
        )
        try outputJSON(output)
    }
}

struct AddressOutput: Codable {
    let unified: String
    let transparent: String
    let sapling: String
}
