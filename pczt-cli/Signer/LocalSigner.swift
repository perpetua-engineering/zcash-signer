//
//  LocalSigner.swift
//  pczt-cli
//
//  Local signer using ZcashSignerCore for Orchard signing.
//  Simulates the watch device signing component.
//

import Foundation
import ZcashSignerCore
import ZcashLightClientKit

// MARK: - Local Signer

struct LocalSigner {
    let ask: ZcashOrchardAsk

    init(askHex: String) throws {
        guard let askData = Data(hex: askHex) else {
            throw LocalSignerError.invalidAsk("Invalid hex encoding")
        }
        self.ask = try ZcashOrchardAsk(bytes: askData)
    }

    init(ask: ZcashOrchardAsk) {
        self.ask = ask
    }

    /// Sign PCZT sighashes and produce signatures.
    func sign(sighashes: PCZTSighashes) throws -> PCZTSignatures {
        try sighashes.validate()

        // Sign Orchard spends
        let orchardSigs = try sighashes.orchardSpends.map { spend -> ShieldedSignature in
            let signature = try ask.signRandomized(
                sighash: sighashes.shieldedSighash,
                alpha: spend.randomizer
            )
            return ShieldedSignature(index: spend.index, signature: signature)
        }

        // Sapling spends would need ask for Sapling (not implemented here)
        // For now, return empty array if no Sapling spends
        let saplingSigs: [ShieldedSignature] = []
        if !sighashes.saplingSpends.isEmpty {
            errorOutput("[Signer] Warning: Sapling signing not implemented, \(sighashes.saplingSpends.count) spends will not be signed")
        }

        // Transparent signing not implemented in this local signer
        // Would require seed access for BIP-44 derivation
        let transparentSigs: [TransparentSignature] = []
        if !sighashes.transparentInputs.isEmpty {
            errorOutput("[Signer] Warning: Transparent signing not implemented, \(sighashes.transparentInputs.count) inputs will not be signed")
        }

        return PCZTSignatures(
            orchardSignatures: orchardSigs,
            saplingSignatures: saplingSigs,
            transparentSignatures: transparentSigs
        )
    }
}

// MARK: - Extended Local Signer (with seed access)

struct ExtendedLocalSigner {
    let seed: Data
    let ask: ZcashOrchardAsk
    let mainnet: Bool

    init(seed: Data, account: UInt32 = 0, mainnet: Bool = true) throws {
        self.seed = seed
        self.mainnet = mainnet
        self.ask = try ZcashOrchardAsk.deriveFromSeed(
            seed,
            coinType: mainnet ? ZSIG_MAINNET_COIN_TYPE : 1,
            account: account
        )
    }

    /// Sign PCZT sighashes including transparent inputs.
    func sign(sighashes: PCZTSighashes) throws -> PCZTSignatures {
        try sighashes.validate()

        // Sign Orchard spends
        let orchardSigs = try sighashes.orchardSpends.map { spend -> ShieldedSignature in
            let signature = try ask.signRandomized(
                sighash: sighashes.shieldedSighash,
                alpha: spend.randomizer
            )
            return ShieldedSignature(index: spend.index, signature: signature)
        }

        // Sapling not implemented
        let saplingSigs: [ShieldedSignature] = []

        // Transparent signing would go here
        // For now, return empty - would need FFI for secp256k1 signing
        let transparentSigs: [TransparentSignature] = []
        if !sighashes.transparentInputs.isEmpty {
            errorOutput("[Signer] Warning: Transparent signing requires FFI extension")
        }

        return PCZTSignatures(
            orchardSignatures: orchardSigs,
            saplingSignatures: saplingSigs,
            transparentSignatures: transparentSigs
        )
    }
}

// MARK: - Errors

enum LocalSignerError: Error, LocalizedError {
    case invalidAsk(String)
    case signingFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidAsk(let reason):
            return "Invalid ASK: \(reason)"
        case .signingFailed(let reason):
            return "Signing failed: \(reason)"
        }
    }
}
