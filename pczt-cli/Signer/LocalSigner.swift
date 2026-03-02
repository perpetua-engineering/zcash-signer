//
//  LocalSigner.swift
//  pczt-cli
//
//  Local signer using ZcashSignerCore's pcztSign to sign raw PCZT bytes.
//  Matches the production signing path used by the watch app.
//

import Foundation
import ZcashSignerCore

// MARK: - Local Signer

struct LocalSigner {
    let orchardSpendingKey: Data
    let saplingAsk: Data

    /// Initialize from a BIP-39 seed, deriving all required keys.
    init(seed: Data, account: UInt32 = 0, mainnet: Bool = true) throws {
        let coinType: UInt32 = mainnet ? ZSIG_MAINNET_COIN_TYPE : 1

        let osk = try ZcashOrchardSpendingKey.deriveFromSeed(
            seed,
            coinType: coinType,
            account: account
        )
        self.orchardSpendingKey = osk.bytes

        let sask = try ZcashSaplingAsk.deriveFromSeed(
            seed,
            coinType: coinType,
            account: account
        )
        self.saplingAsk = sask.bytes
    }

    /// Sign a raw PCZT binary using the full Signer role.
    /// Alpha generation and sighash computation are handled internally.
    func sign(pcztData: Data) throws -> Data {
        try pcztSign(
            pcztData: pcztData,
            orchardSpendingKey: orchardSpendingKey,
            saplingAsk: saplingAsk,
            transparentSecretKey: nil
        )
    }
}

// MARK: - Errors

enum LocalSignerError: Error, LocalizedError {
    case signingFailed(String)

    var errorDescription: String? {
        switch self {
        case .signingFailed(let reason):
            return "Signing failed: \(reason)"
        }
    }
}
