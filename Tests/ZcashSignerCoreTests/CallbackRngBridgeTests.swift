import Foundation
import Security
import XCTest
import ZcashSigner

private func secRandomCallback(_ buffer: UnsafeMutablePointer<UInt8>?, _ length: Int) -> Int32 {
    guard let buffer else { return -1 }
    return SecRandomCopyBytes(kSecRandomDefault, length, buffer)
}

final class CallbackRngBridgeTests: XCTestCase {
    func testSecRandomCallbackSignsAndVerifiesOrchardMessage() {
        let seed = [UInt8](0..<64)
        let message = Array("callback-rng-swift-roundtrip".utf8)

        var ask = ZsigOrchardAsk()
        let deriveAskResult = seed.withUnsafeBytes { seedPtr in
            zsig_derive_orchard_ask_from_seed(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                UInt32(ZSIG_MAINNET_COIN_TYPE),
                0,
                &ask
            )
        }
        XCTAssertEqual(deriveAskResult.rawValue, 0)

        var signatureFFI = ZsigOrchardSignature()
        let signResult = message.withUnsafeBytes { messagePtr in
            zsig_sign_orchard(
                &ask,
                messagePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                message.count,
                &signatureFFI,
                secRandomCallback
            )
        }
        XCTAssertEqual(signResult.rawValue, 0)

        var ak = [UInt8](repeating: 0, count: 32)
        let deriveAkResult = zsig_derive_ak_from_ask(&ask, &ak)
        XCTAssertEqual(deriveAkResult.rawValue, 0)

        let verifyResult = verifyOrchard(ak: ak, message: message, signature: &signatureFFI)
        XCTAssertEqual(verifyResult.rawValue, 0)
    }

    private func verifyOrchard(
        ak: [UInt8],
        message: [UInt8],
        signature: inout ZsigOrchardSignature
    ) -> ZsigError {
        var signatureFFI = ZsigOrchardSignature()
        signatureFFI = signature

        return ak.withUnsafeBytes { akPtr in
            message.withUnsafeBytes { messagePtr in
                zsig_verify_orchard(
                    akPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    messagePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    message.count,
                    &signatureFFI
                )
            }
        }
    }
}
