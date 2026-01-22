//
//  Encoding.swift
//  pczt-cli
//
//  Hex, Base64, and JSON encoding utilities.
//

import Foundation

// MARK: - Hex Encoding

extension Data {
    /// Convert data to hex string.
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from hex string.
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        var index = hex.startIndex

        for _ in 0..<len {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }
}

// MARK: - JSON Encoding

enum JSON {
    static func encode<T: Encodable>(_ value: T, pretty: Bool = true) throws -> String {
        let encoder = Foundation.JSONEncoder()
        if pretty {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        let data = try encoder.encode(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw EncodingError.invalidValue(value, .init(codingPath: [], debugDescription: "Failed to convert to UTF-8"))
        }
        return string
    }

    static func decode<T: Decodable>(_ type: T.Type, from string: String) throws -> T {
        guard let data = string.data(using: .utf8) else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid UTF-8"))
        }
        let decoder = Foundation.JSONDecoder()
        return try decoder.decode(type, from: data)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = Foundation.JSONDecoder()
        return try decoder.decode(type, from: data)
    }
}

// MARK: - CLI Output

func output(_ string: String) {
    print(string)
}

func outputJSON<T: Encodable>(_ value: T) throws {
    let json = try JSON.encode(value)
    output(json)
}

func errorOutput(_ string: String) {
    FileHandle.standardError.write((string + "\n").data(using: .utf8)!)
}
