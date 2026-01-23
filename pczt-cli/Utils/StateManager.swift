//
//  StateManager.swift
//  pczt-cli
//
//  Manages persistent state in ~/.pczt-cli/
//

import Foundation

// MARK: - State Manager

struct StateManager {
    static let shared = StateManager()

    let baseDirectory: URL
    let dataDirectory: URL
    let proposalsDirectory: URL
    let pcztsDirectory: URL
    let walletConfigFile: URL

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        baseDirectory = home.appendingPathComponent(".pczt-cli", isDirectory: true)
        dataDirectory = baseDirectory.appendingPathComponent("data", isDirectory: true)
        proposalsDirectory = baseDirectory.appendingPathComponent("proposals", isDirectory: true)
        pcztsDirectory = baseDirectory.appendingPathComponent("pczts", isDirectory: true)
        walletConfigFile = baseDirectory.appendingPathComponent("wallet.json")
    }

    func ensureDirectories() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
        try fm.createDirectory(at: proposalsDirectory, withIntermediateDirectories: true)
        try fm.createDirectory(at: pcztsDirectory, withIntermediateDirectories: true)
    }

    // MARK: - Wallet Config

    func saveWalletConfig(_ config: WalletConfig) throws {
        try ensureDirectories()
        let encoder = Foundation.JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        try data.write(to: walletConfigFile)
    }

    func loadWalletConfig() throws -> WalletConfig {
        let data = try Data(contentsOf: walletConfigFile)
        return try Foundation.JSONDecoder().decode(WalletConfig.self, from: data)
    }

    func walletConfigExists() -> Bool {
        FileManager.default.fileExists(atPath: walletConfigFile.path)
    }

    // MARK: - Proposals

    func saveProposal(_ proposal: Data, id: String) throws -> URL {
        try ensureDirectories()
        let file = proposalsDirectory.appendingPathComponent("proposal_\(id).bin")
        try proposal.write(to: file)
        return file
    }

    func loadProposal(id: String) throws -> Data {
        let file = proposalsDirectory.appendingPathComponent("proposal_\(id).bin")
        return try Data(contentsOf: file)
    }

    func proposalPath(id: String) -> URL {
        proposalsDirectory.appendingPathComponent("proposal_\(id).bin")
    }

    // MARK: - PCZTs

    func savePCZT(_ pczt: Data, id: String? = nil) throws -> URL {
        try ensureDirectories()
        let actualId = id ?? UUID().uuidString.lowercased()
        let file = pcztsDirectory.appendingPathComponent("pczt_\(actualId).bin")
        try pczt.write(to: file)
        return file
    }

    func loadPCZT(path: String) throws -> Data {
        let url: URL
        if path.hasPrefix("/") {
            url = URL(fileURLWithPath: path)
        } else if path.hasPrefix("./") || path.hasPrefix("../") {
            // Relative to current working directory
            url = URL(fileURLWithPath: path)
        } else {
            // Bare filename - look in pczts directory
            url = pcztsDirectory.appendingPathComponent(path)
        }
        return try Data(contentsOf: url)
    }

    func generatePCZTId() -> String {
        UUID().uuidString.lowercased().prefix(8).description
    }
}

// MARK: - Wallet Config

struct WalletConfig: Codable {
    let ufvk: String
    let network: NetworkType
    let birthday: UInt32
    let lightwalletdURL: String
    let accountIndex: UInt32

    enum NetworkType: String, Codable {
        case mainnet
        case testnet
    }
}

// MARK: - Init Output

struct InitOutput: Codable {
    let ufvk: String
    let ask: String
    let network: String
    let birthday: UInt32
    let transparentAddress: String
}

// MARK: - Sync Output

struct SyncOutput: Codable {
    let synced: Bool
    let latestBlockHeight: UInt64
    let totalBalance: UInt64
    let spendableBalance: UInt64
    let transparentBalance: UInt64
}

// MARK: - Proposal Output

struct ProposalOutput: Codable {
    let proposalId: String
    let type: String
    let transparentInputCount: Int
    let orchardOutputCount: Int
    let fee: UInt64

    enum CodingKeys: String, CodingKey {
        case proposalId = "proposal_id"
        case type
        case transparentInputCount = "transparent_input_count"
        case orchardOutputCount = "orchard_output_count"
        case fee
    }
}

// MARK: - Create PCZT Output

struct CreatePCZTOutput: Codable {
    let pcztFile: String
    let pcztId: String
    let size: Int

    enum CodingKeys: String, CodingKey {
        case pcztFile = "pczt_file"
        case pcztId = "pczt_id"
        case size
    }
}

// MARK: - Sighashes Output

struct SighashesOutput: Codable {
    let shieldedSighash: String
    let orchardSpends: [OrchardSpendOutput]
    let saplingSpends: [SaplingSpendOutput]
    let transparentInputs: [TransparentInputOutput]

    enum CodingKeys: String, CodingKey {
        case shieldedSighash = "shielded_sighash"
        case orchardSpends = "orchard_spends"
        case saplingSpends = "sapling_spends"
        case transparentInputs = "transparent_inputs"
    }
}

struct OrchardSpendOutput: Codable {
    let index: UInt32
    let randomizer: String
    let rk: String?
    let isDummy: Bool?
    let isAlreadySigned: Bool?
    let zip32Derivation: Zip32DerivationOutput?
    let fvk: String?

    enum CodingKeys: String, CodingKey {
        case index
        case randomizer
        case rk
        case isDummy = "dummy"
        case isAlreadySigned = "already_signed"
        case zip32Derivation = "zip32_derivation"
        case fvk
    }
}

struct Zip32DerivationOutput: Codable {
    let seedFingerprint: String
    let derivationPath: [UInt32]

    enum CodingKeys: String, CodingKey {
        case seedFingerprint = "seed_fingerprint"
        case derivationPath = "derivation_path"
    }
}

struct SaplingSpendOutput: Codable {
    let index: UInt32
    let randomizer: String
}

struct TransparentInputOutput: Codable {
    let index: UInt32
    let sighash: String
    let sighashType: UInt8
    let derivationPath: [UInt32]
    let scriptPubKey: String
    let value: UInt64

    enum CodingKeys: String, CodingKey {
        case index
        case sighash
        case sighashType = "sighash_type"
        case derivationPath = "derivation_path"
        case scriptPubKey = "script_pub_key"
        case value
    }
}

// MARK: - Signatures Input/Output

struct SignaturesInput: Codable {
    let orchardSignatures: [ShieldedSignatureInput]
    let saplingSignatures: [ShieldedSignatureInput]
    let transparentSignatures: [TransparentSignatureInput]

    enum CodingKeys: String, CodingKey {
        case orchardSignatures = "orchard_signatures"
        case saplingSignatures = "sapling_signatures"
        case transparentSignatures = "transparent_signatures"
    }
}

struct ShieldedSignatureInput: Codable {
    let index: UInt32
    let signature: String
}

struct TransparentSignatureInput: Codable {
    let index: UInt32
    let signature: String
    let publicKey: String
    let sighashType: UInt8

    enum CodingKeys: String, CodingKey {
        case index
        case signature
        case publicKey = "public_key"
        case sighashType = "sighash_type"
    }
}

// MARK: - Apply Signatures Output

struct ApplySignaturesOutput: Codable {
    let pcztFile: String
    let size: Int

    enum CodingKeys: String, CodingKey {
        case pcztFile = "pczt_file"
        case size
    }
}

// MARK: - Prove Output

struct ProveOutput: Codable {
    let pcztFile: String
    let size: Int

    enum CodingKeys: String, CodingKey {
        case pcztFile = "pczt_file"
        case size
    }
}

// MARK: - Broadcast Output

struct BroadcastOutput: Codable {
    let txid: String
    let success: Bool
}
