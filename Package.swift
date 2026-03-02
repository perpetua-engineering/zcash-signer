// swift-tools-version:5.9
import PackageDescription

// ARCHITECTURE:
// =============
// This package wraps a pre-built Rust library (libzcash_signer) as an xcframework.
// The xcframework is built by build-xcframework.sh and copied to vendor/.
//
// Build flow:
//   1. Run ./build-xcframework.sh to compile Rust for all platforms
//   2. Script creates vendor/ZcashSigner.xcframework
//   3. SPM uses the xcframework as a binary target
//
// This approach follows WalletCoreSPM's pattern and eliminates the need for
// manual LIBRARY_SEARCH_PATHS configuration in consuming Xcode projects.

let package = Package(
    name: "ZcashSigner",
    platforms: [
        .watchOS(.v10),
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "ZcashSignerCore",
            targets: ["ZcashSignerCore"]
        ),
        .executable(
            name: "pczt-cli",
            targets: ["pczt-cli"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(path: "../zcash-swift-wallet-sdk"),
    ],
    targets: [
        // Pre-built Rust library as xcframework
        // Contains libzcash_signer.a + headers for all Apple platforms
        .binaryTarget(
            name: "ZcashSigner",
            path: "vendor/ZcashSigner.xcframework"
        ),

        // Weak secp256k1 C FFI callback stubs needed by libzcash_signer.a
        // when built with pczt-signer feature. Weak so real implementations
        // (e.g. from libzcashlc) win when both are linked.
        .target(
            name: "Secp256k1Stubs",
            path: "Sources/Secp256k1Stubs",
            publicHeadersPath: "include"
        ),

        // Swift wrapper providing safe, idiomatic API
        .target(
            name: "ZcashSignerCore",
            dependencies: ["ZcashSigner", "Secp256k1Stubs"],
            path: "Sources/ZcashSignerSwift"
        ),

        // Stub implementations of WalletCore C FFI symbols referenced by
        // secure-signer in libzcash_signer.a. Only needed by the CLI —
        // the real app links WalletCore.xcframework which provides these.
        .target(
            name: "WalletCoreStubs",
            path: "Sources/WalletCoreStubs"
        ),

        // PCZT CLI tool for testing phone+watch signing flow
        .executableTarget(
            name: "pczt-cli",
            dependencies: [
                "ZcashSignerCore",
                "WalletCoreStubs",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "ZcashLightClientKit", package: "zcash-swift-wallet-sdk"),
            ],
            path: "pczt-cli"
        ),
        .target(
            name: "WalletCoreStubSymbols",
            path: "Tests/WalletCoreStubSymbols",
            publicHeadersPath: "."
        ),
        .testTarget(
            name: "ZcashSignerCoreTests",
            dependencies: [
                "ZcashSigner",
                "WalletCoreStubSymbols"
            ],
            path: "Tests/ZcashSignerCoreTests"
        ),
    ]
)
