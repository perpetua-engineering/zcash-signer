//
//  TestUfvkCommand.swift
//  pczt-cli
//
//  Test UFVK derivation by comparing Orchard and Transparent components against the SDK.
//  Note: We intentionally don't support Sapling, so we compare components rather than full UFVK.
//

import ArgumentParser
import Foundation
import ZcashLightClientKit
import ZcashSignerCore

struct TestUfvkCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "test-ufvk",
        abstract: "Test UFVK derivation against SDK (Orchard + Transparent components)"
    )

    @Flag(name: .long, help: "Verbose output")
    var verbose: Bool = false

    mutating func run() throws {
        // Get seed from environment using SeedManager
        let seed = try SeedManager.parseSeed()

        errorOutput("[Test] Seed: \(seed.count) bytes")

        let derivationTool = DerivationTool(networkType: .mainnet)

        // === SDK Derivation ===
        let usk = try derivationTool.deriveUnifiedSpendingKey(seed: [UInt8](seed), accountIndex: Zip32AccountIndex(0))
        let sdkUfvk = try derivationTool.deriveUnifiedFullViewingKey(from: usk)

        // Get addresses from SDK's UFVK
        let sdkUnifiedAddr = try derivationTool.deriveUnifiedAddressFrom(ufvk: sdkUfvk.stringEncoded)
        let sdkTransparentAddr = try derivationTool.transparentReceiver(from: sdkUnifiedAddr)

        errorOutput("[Test] SDK Transparent: \(sdkTransparentAddr.stringEncoded)")
        errorOutput("[Test] SDK Unified: \(sdkUnifiedAddr.stringEncoded.prefix(40))...")

        // Also derive transparent address directly for comparison
        let directTransparent = try deriveTransparentAddress(
            seed: seed,
            account: 0,
            index: 0,
            mainnet: true
        )
        errorOutput("[Test] Direct Transparent: \(directTransparent)")

        // === Rust Derivation ===
        // First, derive the combined FVK to see raw bytes
        let combinedFvk = try ZcashCombinedFullViewingKey.deriveFromSeed(
            seed,
            coinType: ZSIG_MAINNET_COIN_TYPE,
            account: 0
        )

        if verbose {
            errorOutput("[Test] Rust transparent chain_code: \(combinedFvk.transparentChainCode.hexString)")
            errorOutput("[Test] Rust transparent pubkey: \(combinedFvk.transparentPubkey.hexString)")
        }

        let rustUfvk = try deriveCombinedUFVKString(
            seed: seed,
            coinType: ZSIG_MAINNET_COIN_TYPE,
            account: 0,
            mainnet: true
        )

        errorOutput("[Test] Rust UFVK length: \(rustUfvk.count) chars")
        errorOutput("[Test] SDK UFVK length: \(sdkUfvk.stringEncoded.count) chars")

        // Try to get addresses from our Rust UFVK
        var rustTransparentAddrStr = "N/A (UFVK decode failed)"
        var rustUnifiedAddrStr = "N/A"
        do {
            let rustUnifiedAddr = try derivationTool.deriveUnifiedAddressFrom(ufvk: rustUfvk)
            let rustTransparentAddr = try derivationTool.transparentReceiver(from: rustUnifiedAddr)
            rustTransparentAddrStr = rustTransparentAddr.stringEncoded
            rustUnifiedAddrStr = rustUnifiedAddr.stringEncoded
            errorOutput("[Test] Rust Transparent: \(rustTransparentAddrStr)")
            errorOutput("[Test] Rust Unified: \(rustUnifiedAddrStr.prefix(40))...")
        } catch {
            errorOutput("[Test] Failed to decode Rust UFVK: \(error)")
            errorOutput("[Test] Rust UFVK: \(rustUfvk)")
        }

        // === Compare Components ===
        let transparentMatch = sdkTransparentAddr.stringEncoded == rustTransparentAddrStr

        // For Orchard, extract just the Orchard receiver from both UAs
        // The SDK's UA has Sapling+Orchard+Transparent, ours has Orchard+Transparent
        // But the Orchard component should be the same
        let sdkOrchardReceiver = extractOrchardReceiver(from: sdkUnifiedAddr.stringEncoded)
        let rustOrchardReceiver = extractOrchardReceiver(from: rustUnifiedAddrStr)
        let orchardMatch = sdkOrchardReceiver == rustOrchardReceiver

        if verbose {
            errorOutput("[Test] SDK UFVK:  \(sdkUfvk.stringEncoded)")
            errorOutput("[Test] Rust UFVK: \(rustUfvk)")
            if let sdkO = sdkOrchardReceiver, let rustO = rustOrchardReceiver {
                errorOutput("[Test] SDK Orchard:  \(sdkO.prefix(40))...")
                errorOutput("[Test] Rust Orchard: \(rustO.prefix(40))...")
            }
        }

        let output = TestOutput(
            transparentMatch: transparentMatch,
            orchardMatch: orchardMatch,
            sdkTransparent: sdkTransparentAddr.stringEncoded,
            rustTransparent: rustTransparentAddrStr,
            sdkUfvk: sdkUfvk.stringEncoded,
            rustUfvk: rustUfvk
        )
        try outputJSON(output)

        if rustTransparentAddrStr.contains("N/A") {
            errorOutput("[Test] FAILED - Could not decode Rust UFVK")
            throw ExitCode.failure
        }

        if !transparentMatch {
            errorOutput("[Test] MISMATCH - Transparent addresses don't match!")
            throw ExitCode.failure
        }

        if !orchardMatch {
            errorOutput("[Test] MISMATCH - Orchard receivers don't match!")
            throw ExitCode.failure
        }

        errorOutput("[Test] SUCCESS - Orchard and Transparent components match!")
    }

    /// Extract Orchard receiver bytes from a Unified Address for comparison
    /// Returns hex-encoded Orchard receiver (diversifier + pk_d = 43 bytes) or nil
    private func extractOrchardReceiver(from ua: String) -> String? {
        // Step 1: Bech32m decode
        guard let (_, data5bit) = bech32mDecode(ua) else {
            errorOutput("[Extract] Bech32m decode failed")
            return nil
        }

        // Step 2: Convert from 5-bit to 8-bit
        guard let data8bit = convert5to8(data5bit) else {
            errorOutput("[Extract] 5-to-8 bit conversion failed")
            return nil
        }

        // Step 3: F4Jumble inverse (unjumble)
        guard let raw = f4JumbleInverse(data8bit) else {
            errorOutput("[Extract] F4Jumble inverse failed")
            return nil
        }

        // Step 4: Parse TLV and find Orchard receiver (typecode 0x03)
        // Raw format: [TLV receivers...] || [HRP padding to 16 bytes]
        // Strip the 16-byte HRP padding at the end
        let tlvData = Array(raw.dropLast(16))

        var offset = 0
        while offset + 2 <= tlvData.count {
            let typecode = tlvData[offset]
            let length = Int(tlvData[offset + 1])
            offset += 2

            if offset + length > tlvData.count {
                break
            }

            if typecode == 0x03 && length == 43 {
                // Found Orchard receiver: 11-byte diversifier + 32-byte pk_d
                let receiver = Array(tlvData[offset..<(offset + length)])
                return receiver.map { String(format: "%02x", $0) }.joined()
            }

            offset += length
        }

        errorOutput("[Extract] No Orchard receiver found in TLV")
        return nil
    }

    /// Bech32m decode - returns (hrp, 5-bit data) or nil on failure
    private func bech32mDecode(_ str: String) -> (String, [UInt8])? {
        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        let charsetMap: [Character: UInt8] = Dictionary(
            uniqueKeysWithValues: charset.enumerated().map { (charset[charset.index(charset.startIndex, offsetBy: $0.offset)], UInt8($0.offset)) }
        )

        guard let separatorIndex = str.lastIndex(of: "1") else { return nil }
        let hrp = String(str[..<separatorIndex]).lowercased()
        let dataPart = str[str.index(after: separatorIndex)...]

        guard dataPart.count >= 6 else { return nil }  // checksum is 6 chars

        var data5bit: [UInt8] = []
        for char in dataPart {
            guard let value = charsetMap[char] else { return nil }
            data5bit.append(value)
        }

        // Verify checksum (Bech32m constant = 0x2bc830a3)
        if !verifyBech32mChecksum(hrp: hrp, data: data5bit) {
            return nil
        }

        // Remove checksum (last 6 values)
        return (hrp, Array(data5bit.dropLast(6)))
    }

    private func verifyBech32mChecksum(hrp: String, data: [UInt8]) -> Bool {
        let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

        func polymod(_ values: [UInt8]) -> UInt32 {
            var chk: UInt32 = 1
            for v in values {
                let top = chk >> 25
                chk = ((chk & 0x1ffffff) << 5) ^ UInt32(v)
                for (i, g) in gen.enumerated() {
                    if (top >> i) & 1 == 1 {
                        chk ^= g
                    }
                }
            }
            return chk
        }

        var values: [UInt8] = []
        for c in hrp { values.append(UInt8(c.asciiValue! >> 5)) }
        values.append(0)
        for c in hrp { values.append(UInt8(c.asciiValue! & 0x1f)) }
        values.append(contentsOf: data)

        return polymod(values) == 0x2bc830a3
    }

    /// Convert 5-bit groups to 8-bit bytes
    private func convert5to8(_ data: [UInt8]) -> [UInt8]? {
        var acc: UInt32 = 0
        var bits = 0
        var result: [UInt8] = []

        for value in data {
            if value >= 32 { return nil }
            acc = (acc << 5) | UInt32(value)
            bits += 5
            while bits >= 8 {
                bits -= 8
                result.append(UInt8((acc >> bits) & 0xff))
            }
        }

        // Any remaining bits should be padding zeros
        if bits > 0 {
            let remaining = (acc << (8 - bits)) & 0xff
            if remaining != 0 {
                // Non-zero padding is technically invalid but we'll ignore for extraction
            }
        }

        return result
    }

    /// F4Jumble inverse (unjumble)
    private func f4JumbleInverse(_ data: [UInt8]) -> [UInt8]? {
        guard data.count >= 48 && data.count <= 4194368 else { return nil }

        let len = data.count
        let leftLen = min(64, len / 2)

        var left = Array(data[..<leftLen])
        var right = Array(data[leftLen...])

        // Reverse of: G(0), H(0), G(1), H(1)
        // So we do: H(1)^-1, G(1)^-1, H(0)^-1, G(0)^-1
        // But XOR is self-inverse, so just repeat in reverse order: H(1), G(1), H(0), G(0)

        hRound(&left, right, 1)
        gRound(left, &right, 1)
        hRound(&left, right, 0)
        gRound(left, &right, 0)

        return left + right
    }

    private func hRound(_ left: inout [UInt8], _ right: [UInt8], _ round: UInt8) {
        // H personaliation: "UA_F4Jumble_H" || round || 0 || 0
        var pers = [UInt8](repeating: 0, count: 16)
        let prefix = "UA_F4Jumble_H".utf8
        for (i, b) in prefix.enumerated() { pers[i] = b }
        pers[13] = round

        let hash = blake2bHash(data: right, personalization: pers, outputLen: left.count)
        for i in 0..<left.count {
            left[i] ^= hash[i]
        }
    }

    private func gRound(_ left: [UInt8], _ right: inout [UInt8], _ round: UInt8) {
        let chunks = (right.count + 63) / 64
        for j in 0..<chunks {
            var pers = [UInt8](repeating: 0, count: 16)
            let prefix = "UA_F4Jumble_G".utf8
            for (i, b) in prefix.enumerated() { pers[i] = b }
            pers[13] = round
            pers[14] = UInt8(j & 0xff)
            pers[15] = UInt8((j >> 8) & 0xff)

            let hash = blake2bHash(data: left, personalization: pers, outputLen: 64)
            let start = j * 64
            let end = min(start + 64, right.count)
            for i in start..<end {
                right[i] ^= hash[i - start]
            }
        }
    }

    private func blake2bHash(data: [UInt8], personalization: [UInt8], outputLen: Int) -> [UInt8] {
        // Use zsig_blake2b from our Rust library via FFI
        var output = [UInt8](repeating: 0, count: outputLen)
        data.withUnsafeBufferPointer { dataPtr in
            personalization.withUnsafeBufferPointer { persPtr in
                output.withUnsafeMutableBufferPointer { outPtr in
                    // Call our Rust BLAKE2b function
                    _ = zsig_blake2b_personal(
                        persPtr.baseAddress,
                        16,
                        dataPtr.baseAddress,
                        data.count,
                        outPtr.baseAddress,
                        outputLen
                    )
                }
            }
        }
        return output
    }
}

// BLAKE2b FFI declaration - add to zcash_signer.h and implement in Rust
@_silgen_name("zsig_blake2b_personal")
func zsig_blake2b_personal(
    _ personal: UnsafePointer<UInt8>?,
    _ personal_len: Int,
    _ data: UnsafePointer<UInt8>?,
    _ data_len: Int,
    _ output: UnsafeMutablePointer<UInt8>?,
    _ output_len: Int
) -> Int32

struct TestOutput: Codable {
    let transparentMatch: Bool
    let orchardMatch: Bool
    let sdkTransparent: String
    let rustTransparent: String
    let sdkUfvk: String
    let rustUfvk: String
}
