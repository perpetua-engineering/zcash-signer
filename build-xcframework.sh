#!/bin/bash
#
# Build ZcashSigner.xcframework for iOS/watchOS/macOS
#
# This script compiles the Rust library for all required Apple targets
# using -Z build-std for tier-3 targets (watchOS), then packages them
# into an xcframework that SPM can use via .binaryTarget.
#
# Targets:
#   watchOS Device:
#     - aarch64-apple-watchos       (Apple Watch Series 4+)
#     - arm64_32-apple-watchos      (Apple Watch Series 3 and earlier)
#   watchOS Simulator:
#     - aarch64-apple-watchos-sim   (Apple Silicon Macs)
#     - x86_64-apple-watchos-sim    (Intel Macs)
#   iOS Device:
#     - aarch64-apple-ios           (iPhone/iPad)
#   iOS Simulator:
#     - aarch64-apple-ios-sim       (Apple Silicon Macs)
#     - x86_64-apple-ios            (Intel Macs)
#   macOS:
#     - aarch64-apple-darwin        (Apple Silicon Macs)
#     - x86_64-apple-darwin         (Intel Macs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="$SCRIPT_DIR/target"
XCFRAMEWORK_DIR="$SCRIPT_DIR/ZcashSigner.xcframework"
HEADER_DIR="$BUILD_DIR/headers"

echo "Building ZcashSigner for Apple platforms..."
echo ""

# Build a tier-3 target (requires -Z build-std)
build_tier3() {
    local target=$1
    local name=$2
    echo "==> Building $name ($target)"
    cargo +nightly build \
        -Z build-std=core,alloc \
        --target "$target" \
        --release 2>&1 | grep -E "(Compiling|Finished|error|warning:)" || true
}

# Build a tier-2 target (standard rustup target)
build_tier2() {
    local target=$1
    local name=$2
    echo "==> Building $name ($target)"
    # Ensure target is installed
    rustup target add "$target" 2>/dev/null || true
    cargo +nightly build \
        --target "$target" \
        --release 2>&1 | grep -E "(Compiling|Finished|error|warning:)" || true
}

# watchOS Device (tier-3, needs build-std)
build_tier3 "aarch64-apple-watchos" "watchOS Device (arm64)"
build_tier3 "arm64_32-apple-watchos" "watchOS Device (arm64_32)"

# watchOS Simulator (tier-3, needs build-std)
build_tier3 "aarch64-apple-watchos-sim" "watchOS Simulator (arm64)"
build_tier3 "x86_64-apple-watchos-sim" "watchOS Simulator (x86_64)"

# iOS Device (tier-2)
build_tier2 "aarch64-apple-ios" "iOS Device (arm64)"

# iOS Simulator (tier-2)
build_tier2 "aarch64-apple-ios-sim" "iOS Simulator (arm64)"
build_tier2 "x86_64-apple-ios" "iOS Simulator (x86_64)"

# macOS (tier-2) - for unit testing on host
build_tier2 "aarch64-apple-darwin" "macOS (arm64)"
build_tier2 "x86_64-apple-darwin" "macOS (x86_64)"

echo ""
echo "==> Creating universal libraries with lipo..."

# Create output directories
mkdir -p "$BUILD_DIR/watchos-device-universal"
mkdir -p "$BUILD_DIR/watchos-sim-universal"
mkdir -p "$BUILD_DIR/ios-device"
mkdir -p "$BUILD_DIR/ios-sim-universal"
mkdir -p "$BUILD_DIR/macos-universal"

# watchOS Device: arm64 + arm64_32 → universal
lipo -create \
    "$BUILD_DIR/aarch64-apple-watchos/release/libzcash_signer.a" \
    "$BUILD_DIR/arm64_32-apple-watchos/release/libzcash_signer.a" \
    -output "$BUILD_DIR/watchos-device-universal/libzcash_signer.a"
echo "Created watchos-device-universal/libzcash_signer.a"

# watchOS Simulator: arm64 + x86_64 → universal
lipo -create \
    "$BUILD_DIR/aarch64-apple-watchos-sim/release/libzcash_signer.a" \
    "$BUILD_DIR/x86_64-apple-watchos-sim/release/libzcash_signer.a" \
    -output "$BUILD_DIR/watchos-sim-universal/libzcash_signer.a"
echo "Created watchos-sim-universal/libzcash_signer.a"

# iOS Device: just arm64 (no 32-bit iOS anymore)
cp "$BUILD_DIR/aarch64-apple-ios/release/libzcash_signer.a" \
   "$BUILD_DIR/ios-device/libzcash_signer.a"
echo "Created ios-device/libzcash_signer.a"

# iOS Simulator: arm64 + x86_64 → universal
lipo -create \
    "$BUILD_DIR/aarch64-apple-ios-sim/release/libzcash_signer.a" \
    "$BUILD_DIR/x86_64-apple-ios/release/libzcash_signer.a" \
    -output "$BUILD_DIR/ios-sim-universal/libzcash_signer.a"
echo "Created ios-sim-universal/libzcash_signer.a"

# macOS: arm64 + x86_64 → universal
lipo -create \
    "$BUILD_DIR/aarch64-apple-darwin/release/libzcash_signer.a" \
    "$BUILD_DIR/x86_64-apple-darwin/release/libzcash_signer.a" \
    -output "$BUILD_DIR/macos-universal/libzcash_signer.a"
echo "Created macos-universal/libzcash_signer.a"

echo ""
echo "==> Staging headers..."
rm -rf "$HEADER_DIR"
mkdir -p "$HEADER_DIR"

# Copy header
cp "$SCRIPT_DIR/include/zcash_signer.h" "$HEADER_DIR/"

# Create modulemap
cat > "$HEADER_DIR/module.modulemap" << 'EOF'
module ZcashSignerLib {
    header "zcash_signer.h"
    export *
}
EOF

echo ""
echo "==> Creating XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"

xcodebuild -create-xcframework \
    -library "$BUILD_DIR/ios-device/libzcash_signer.a" \
    -headers "$HEADER_DIR" \
    -library "$BUILD_DIR/ios-sim-universal/libzcash_signer.a" \
    -headers "$HEADER_DIR" \
    -library "$BUILD_DIR/watchos-device-universal/libzcash_signer.a" \
    -headers "$HEADER_DIR" \
    -library "$BUILD_DIR/watchos-sim-universal/libzcash_signer.a" \
    -headers "$HEADER_DIR" \
    -output "$XCFRAMEWORK_DIR"

echo ""
echo "==> Library sizes:"
for lib in watchos-device-universal watchos-sim-universal ios-device ios-sim-universal macos-universal; do
    size=$(ls -lh "$BUILD_DIR/$lib/libzcash_signer.a" | awk '{print $5}')
    echo "  $lib: $size"
done

echo ""
echo "==> Verifying architectures:"
for lib in watchos-device-universal watchos-sim-universal ios-device ios-sim-universal macos-universal; do
    archs=$(lipo -info "$BUILD_DIR/$lib/libzcash_signer.a" 2>/dev/null | sed 's/.*: //')
    echo "  $lib: $archs"
done

echo ""
echo "==> XCFramework contents:"
ls -la "$XCFRAMEWORK_DIR"

echo ""
echo "==> Exported symbols (sample):"
nm -g "$BUILD_DIR/aarch64-apple-watchos/release/libzcash_signer.a" 2>/dev/null | grep " T _zsig_" | head -5

echo ""
echo "Done! XCFramework created at: $XCFRAMEWORK_DIR"
