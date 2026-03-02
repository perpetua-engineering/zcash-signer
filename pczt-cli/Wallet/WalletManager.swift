//
//  WalletManager.swift
//  pczt-cli
//
//  SDK synchronizer wrapper for view-only wallet operations.
//

import Foundation
import ZcashLightClientKit

// MARK: - Wallet Manager

actor WalletManager {
    private let synchronizer: SDKSynchronizer
    private let accountUUID: AccountUUID
    private let network: ZcashNetwork
    private let verbose: Bool

    init(
        ufvk: String,
        birthday: UInt32,
        lightwalletdURL: String,
        network: NetworkType,
        verbose: Bool = false
    ) async throws {
        self.verbose = verbose
        self.network = network == .mainnet
            ? ZcashNetworkBuilder.network(for: .mainnet)
            : ZcashNetworkBuilder.network(for: .testnet)

        let endpoint = try WalletManager.parseEndpoint(from: lightwalletdURL)
        let urls = try WalletManager.prepareUrls(network: network)

        let initializer = Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: urls.fsBlockDbRoot,
            generalStorageURL: urls.generalStorageURL,
            dataDbURL: urls.dataDbURL,
            torDirURL: urls.torDirURL,
            endpoint: endpoint,
            network: self.network,
            spendParamsURL: urls.spendParamsURL,
            outputParamsURL: urls.outputParamsURL,
            saplingParamsSourceURL: SaplingParamsSourceURL.default,
            alias: .custom("pczt_cli"),
            loggingPolicy: verbose ? .default(.debug) : .default(.warning),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let synchronizer = SDKSynchronizer(initializer: initializer)

        _ = try await synchronizer.prepare(
            with: nil,
            walletBirthday: BlockHeight(Int(birthday)),
            for: .newWallet,
            name: "pczt-cli",
            keySource: "local"
        )

        // Check if account already exists from a previous run
        let existingAccounts = try await synchronizer.listAccounts()
        let accountUUID: AccountUUID
        if let existing = existingAccounts.first {
            accountUUID = existing.id
        } else {
            accountUUID = try await synchronizer.importAccount(
                ufvk: ufvk,
                seedFingerprint: nil,
                zip32AccountIndex: nil,
                purpose: .viewOnly,
                name: "pczt-cli",
                keySource: "local"
            )
        }

        self.synchronizer = synchronizer
        self.accountUUID = accountUUID
    }

    // MARK: - Sync

    func sync(timeoutSeconds: Int = 3600) async throws {
        try await synchronizer.start(retry: true)
        try await waitForSync(timeoutSeconds: timeoutSeconds)
    }

    func stop() {
        synchronizer.stop()
    }

    // MARK: - Balances

    func getBalances() -> (total: Zatoshi, spendable: Zatoshi, transparent: Zatoshi) {
        let state = synchronizer.latestState
        guard let balance = state.accountsBalances[accountUUID] else {
            return (.zero, .zero, .zero)
        }

        let total = (balance.saplingBalance.total()) + (balance.orchardBalance.total())
        let spendable = (balance.saplingBalance.spendableValue) + (balance.orchardBalance.spendableValue)
        let transparent = balance.unshielded

        return (total, spendable, transparent)
    }

    func getLatestBlockHeight() -> BlockHeight {
        synchronizer.latestState.latestBlockHeight
    }

    // MARK: - Proposals

    func proposeShielding(threshold: Zatoshi, memo: Memo?) async throws -> Proposal {
        // proposeShielding requires a non-optional Memo, so provide empty if nil
        let memoToUse = memo ?? .empty
        guard let proposal = try await synchronizer.proposeShielding(
            accountUUID: accountUUID,
            shieldingThreshold: threshold,
            memo: memoToUse,
            transparentReceiver: nil
        ) else {
            throw WalletManagerError.proposalFailed("No spendable transparent funds meet threshold")
        }
        return proposal
    }

    func proposeTransfer(to recipient: String, amount: Zatoshi, memo: Memo?) async throws -> Proposal {
        let recipientObj = try Recipient(recipient, network: network.networkType)
        return try await synchronizer.proposeTransfer(
            accountUUID: accountUUID,
            recipient: recipientObj,
            amount: amount,
            memo: memo
        )
    }

    // MARK: - PCZT Operations

    func createPCZT(from proposal: Proposal) async throws -> Data {
        try await synchronizer.createPCZTFromProposal(accountUUID: accountUUID, proposal: proposal)
    }

    func addProofs(to pczt: Data) async throws -> Data {
        try await synchronizer.addProofsToPCZT(pczt: pczt)
    }

    func broadcast(pcztWithProofs: Data, pcztWithSigs: Data) async throws -> String {
        let results = try await synchronizer.createTransactionFromPCZT(
            pcztWithProofs: pcztWithProofs,
            pcztWithSigs: pcztWithSigs
        )

        for try await result in results {
            switch result {
            case .success(let txId):
                return txId.hexString
            case .grpcFailure(_, let error):
                throw WalletManagerError.broadcastFailed(error.localizedDescription)
            case .submitFailure(_, let code, let description):
                throw WalletManagerError.broadcastFailed("\(code): \(description)")
            case .notAttempted:
                continue
            }
        }

        throw WalletManagerError.broadcastFailed("No transaction submitted")
    }

    // MARK: - Addresses

    func getTransparentAddress() async throws -> String {
        let address = try await synchronizer.getTransparentAddress(accountUUID: accountUUID)
        return address.stringEncoded
    }

    // MARK: - Private

    private func waitForSync(timeoutSeconds: Int) async throws {
        let start = Date()
        let deadline = start.addingTimeInterval(TimeInterval(timeoutSeconds))
        var lastPercent: Int?

        while Date() < deadline {
            let status = synchronizer.latestState.syncStatus
            if status.isSynced {
                return
            }

            if case .error(let error) = status {
                if shouldRetrySync(after: error) {
                    errorOutput("[Wallet] Sync error, retrying: \(error)")
                    synchronizer.stop()
                    try await Task.sleep(nanoseconds: 2_000_000_000)
                    try await synchronizer.start(retry: true)
                } else {
                    throw error
                }
            }

            if case let .syncing(progress, _) = status {
                let percent = max(0, min(100, Int((progress * 100).rounded())))
                if percent != lastPercent {
                    errorOutput("[Wallet] Sync progress: \(percent)%")
                    lastPercent = percent
                }
            }

            try await Task.sleep(nanoseconds: 1_000_000_000)
        }

        let elapsed = Int(Date().timeIntervalSince(start))
        throw WalletManagerError.syncTimeout(elapsed)
    }

    private func shouldRetrySync(after error: Error) -> Bool {
        if let zcashError = error as? ZcashError {
            switch zcashError {
            case .serviceGetInfoFailed,
                 .serviceLatestBlockFailed,
                 .serviceLatestBlockHeightFailed,
                 .serviceBlockRangeFailed:
                return true
            default:
                return false
            }
        }
        return false
    }

    private static func parseEndpoint(from urlString: String) throws -> LightWalletEndpoint {
        guard let url = URL(string: urlString), let host = url.host else {
            throw WalletManagerError.invalidEndpoint(urlString)
        }
        let port = url.port ?? (url.scheme == "https" ? 443 : 9067)
        let secure = url.scheme == "https"
        return LightWalletEndpoint(address: host, port: port, secure: secure)
    }

    private static func prepareUrls(network: NetworkType) throws -> WalletUrls {
        let stateManager = StateManager.shared
        try stateManager.ensureDirectories()

        let networkDir = stateManager.dataDirectory.appendingPathComponent(
            network == .mainnet ? "mainnet" : "testnet",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: networkDir, withIntermediateDirectories: true)

        return WalletUrls(
            fsBlockDbRoot: networkDir.appendingPathComponent(ZcashSDK.defaultFsCacheName, isDirectory: true),
            generalStorageURL: networkDir.appendingPathComponent("general_storage", isDirectory: true),
            dataDbURL: networkDir.appendingPathComponent("data.db"),
            torDirURL: networkDir.appendingPathComponent(ZcashSDK.defaultTorDirName, isDirectory: true),
            spendParamsURL: stateManager.baseDirectory.appendingPathComponent("sapling-spend.params"),
            outputParamsURL: stateManager.baseDirectory.appendingPathComponent("sapling-output.params")
        )
    }
}

// MARK: - Supporting Types

struct WalletUrls {
    let fsBlockDbRoot: URL
    let generalStorageURL: URL
    let dataDbURL: URL
    let torDirURL: URL
    let spendParamsURL: URL
    let outputParamsURL: URL
}

enum NetworkType: String, CaseIterable {
    case mainnet
    case testnet
}

// MARK: - Errors

enum WalletManagerError: Error, LocalizedError {
    case notInitialized(String)
    case invalidEndpoint(String)
    case proposalFailed(String)
    case broadcastFailed(String)
    case syncTimeout(Int)

    var errorDescription: String? {
        switch self {
        case .notInitialized(let reason):
            return "Wallet not initialized: \(reason)"
        case .invalidEndpoint(let value):
            return "Invalid lightwalletd endpoint: \(value)"
        case .proposalFailed(let reason):
            return "Proposal failed: \(reason)"
        case .broadcastFailed(let reason):
            return "Broadcast failed: \(reason)"
        case .syncTimeout(let seconds):
            return "Sync timed out after \(seconds) seconds"
        }
    }
}
