// swift-tools-version:5.9
import PackageDescription

// ARCHITECTURE NOTE:
// ==================
// This package provides C headers and Swift wrapper. The actual libzcash_signer.a
// library linking is configured in the Xcode project's build settings with
// SDK-conditional LIBRARY_SEARCH_PATHS:
//
//   LIBRARY_SEARCH_PATHS[sdk=watchos*] = $(PROJECT_DIR)/zcash-signer/target/watchos-device-universal
//   LIBRARY_SEARCH_PATHS[sdk=watchsimulator*] = $(PROJECT_DIR)/zcash-signer/target/watchos-sim-universal
//
// We cannot use SPM's linkerSettings because:
// 1. SPM evaluates Package.swift at resolution time, not build time
// 2. .when(platforms:) only distinguishes platforms, not device vs simulator
// 3. binaryTarget with xcframework causes modulemap conflicts with WalletCore.xcframework

let zcashSignerPath = "./target"
let macOSLibPath = "\(zcashSignerPath)/macos-universal"

let package = Package(
    name: "ZcashSigner",
    platforms: [
        .watchOS(.v10),
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "ZcashSignerLocal",
            targets: ["ZcashSignerCore"]
        ),
    ],
    targets: [
        // C header declarations - library path comes from Xcode build settings
        .target(
            name: "CZcashSigner",
            path: "Sources/CZcashSigner",
            linkerSettings: [
                .linkedLibrary("zcash_signer"),
                // macOS path for tests (watchOS/iOS paths in Xcode project settings)
                .unsafeFlags(["-L\(macOSLibPath)"], .when(platforms: [.macOS])),
            ]
        ),
        // Swift wrapper
        .target(
            name: "ZcashSignerCore",
            dependencies: ["CZcashSigner"],
            path: "Sources/ZcashSignerSwift"
        ),
    ]
)
