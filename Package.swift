// swift-tools-version:5.9
import PackageDescription

// ARCHITECTURE:
// =============
// This package wraps a pre-built Rust library (libzcash_signer) as an xcframework.
// The xcframework is built by build-xcframework.sh and copied to Vendor/.
//
// Build flow:
//   1. Run ./build-xcframework.sh to compile Rust for all platforms
//   2. Script creates Vendor/ZcashSigner.xcframework
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
    ],
    dependencies: [],
    targets: [
        // Pre-built Rust library as xcframework
        // Contains libzcash_signer.a + headers for all Apple platforms
        .binaryTarget(
            name: "ZcashSigner",
            path: "Vendor/ZcashSigner.xcframework"
        ),

        // Swift wrapper providing safe, idiomatic API
        .target(
            name: "ZcashSignerCore",
            dependencies: ["ZcashSigner"],
            path: "Sources/ZcashSignerSwift"
        ),
    ]
)
