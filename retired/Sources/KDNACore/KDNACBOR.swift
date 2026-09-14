import Foundation
import CoreFoundation

public enum KDNACBORError: Error, Equatable {
    case truncated
    case unsupported(String)
    case invalid(String)
}

/// Minimal deterministic CBOR support for KDNA wire values.
///
/// KDNA payloads use JSON-compatible maps, arrays, strings, numbers,
/// booleans and null. Encrypted envelopes may additionally contain byte
/// strings. Indefinite-length items and application tags are rejected so an
/// unsupported wire shape fails closed instead of being guessed.
public enum KDNACBOR {
    public static func decode(_ data: Data) throws -> Any {
        var decoder = Decoder(bytes: [UInt8](data))
        let value = try decoder.readValue()
        guard decoder.isAtEnd else {
            throw KDNACBORError.invalid("trailing bytes after CBOR value")
        }
        return value
    }

    public static func decodeObject(_ data: Data) throws -> [String: Any] {
        guard let object = try decode(data) as? [String: Any] else {
            throw KDNACBORError.invalid("CBOR root must be a string-keyed map")
        }
        return object
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let value = jsonCompatible(try decode(data))
        guard JSONSerialization.isValidJSONObject(value) else {
            throw KDNACBORError.invalid("CBOR value cannot be represented for Codable decoding")
        }
        let json = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        return try JSONDecoder().decode(type, from: json)
    }

    public static func encode(_ value: Any) throws -> Data {
        var bytes: [UInt8] = []
        try append(value, to: &bytes)
        return Data(bytes)
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let json = try JSONEncoder().encode(value)
        let object = try JSONSerialization.jsonObject(with: json)
        return try encode(object)
    }

    private static func jsonCompatible(_ value: Any) -> Any {
        if let data = value as? Data { return data.base64EncodedString() }
        if let array = value as? [Any] { return array.map(jsonCompatible) }
        if let map = value as? [String: Any] {
            return map.mapValues(jsonCompatible)
        }
        return value
    }

    private static func append(_ value: Any, to bytes: inout [UInt8]) throws {
        switch value {
        case is NSNull:
            bytes.append(0xf6)
        case let value as Bool:
            bytes.append(value ? 0xf5 : 0xf4)
        case let value as Data:
            appendHeader(major: 2, value: UInt64(value.count), to: &bytes)
            bytes.append(contentsOf: value)
        case let value as String:
            let utf8 = Array(value.utf8)
            appendHeader(major: 3, value: UInt64(utf8.count), to: &bytes)
            bytes.append(contentsOf: utf8)
        case let value as [Any]:
            appendHeader(major: 4, value: UInt64(value.count), to: &bytes)
            for item in value { try append(item, to: &bytes) }
        case let value as [String: Any]:
            let keys = value.keys.sorted()
            appendHeader(major: 5, value: UInt64(keys.count), to: &bytes)
            for key in keys {
                try append(key, to: &bytes)
                try append(value[key] as Any, to: &bytes)
            }
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                bytes.append(value.boolValue ? 0xf5 : 0xf4)
            } else if value.doubleValue.rounded() == value.doubleValue {
                let integer = value.int64Value
                if integer >= 0 {
                    appendHeader(major: 0, value: UInt64(integer), to: &bytes)
                } else {
                    appendHeader(major: 1, value: UInt64(-1 - integer), to: &bytes)
                }
            } else {
                bytes.append(0xfb)
                var bits = value.doubleValue.bitPattern.bigEndian
                withUnsafeBytes(of: &bits) { bytes.append(contentsOf: $0) }
            }
        case let value as Int:
            if value >= 0 {
                appendHeader(major: 0, value: UInt64(value), to: &bytes)
            } else {
                appendHeader(major: 1, value: UInt64(-1 - value), to: &bytes)
            }
        case let value as Double:
            bytes.append(0xfb)
            var bits = value.bitPattern.bigEndian
            withUnsafeBytes(of: &bits) { bytes.append(contentsOf: $0) }
        default:
            throw KDNACBORError.unsupported("unsupported CBOR value type: \(type(of: value))")
        }
    }

    private static func appendHeader(major: UInt8, value: UInt64, to bytes: inout [UInt8]) {
        if value < 24 {
            bytes.append((major << 5) | UInt8(value))
        } else if value <= UInt8.max {
            bytes.append((major << 5) | 24)
            bytes.append(UInt8(value))
        } else if value <= UInt16.max {
            bytes.append((major << 5) | 25)
            var encoded = UInt16(value).bigEndian
            withUnsafeBytes(of: &encoded) { bytes.append(contentsOf: $0) }
        } else if value <= UInt32.max {
            bytes.append((major << 5) | 26)
            var encoded = UInt32(value).bigEndian
            withUnsafeBytes(of: &encoded) { bytes.append(contentsOf: $0) }
        } else {
            bytes.append((major << 5) | 27)
            var encoded = value.bigEndian
            withUnsafeBytes(of: &encoded) { bytes.append(contentsOf: $0) }
        }
    }

    private struct Decoder {
        let bytes: [UInt8]
        var offset = 0

        var isAtEnd: Bool { offset == bytes.count }

        mutating func readValue() throws -> Any {
            let initial = try readByte()
            let major = initial >> 5
            let additional = initial & 0x1f

            switch major {
            case 0:
                return NSNumber(value: try readLength(additional))
            case 1:
                let raw = try readLength(additional)
                guard raw <= UInt64(Int64.max) else {
                    throw KDNACBORError.unsupported("negative integer exceeds Int64")
                }
                return NSNumber(value: -1 - Int64(raw))
            case 2:
                return Data(try readBytes(count: Int(try readLength(additional))))
            case 3:
                let data = Data(try readBytes(count: Int(try readLength(additional))))
                guard let string = String(data: data, encoding: .utf8) else {
                    throw KDNACBORError.invalid("invalid UTF-8 text string")
                }
                return string
            case 4:
                let count = Int(try readLength(additional))
                return try (0..<count).map { _ in try readValue() }
            case 5:
                let count = Int(try readLength(additional))
                var map: [String: Any] = [:]
                for _ in 0..<count {
                    guard let key = try readValue() as? String else {
                        throw KDNACBORError.unsupported("KDNA CBOR map keys must be strings")
                    }
                    map[key] = try readValue()
                }
                return map
            case 6:
                throw KDNACBORError.unsupported("CBOR tags are not part of the KDNA wire contract")
            case 7:
                return try readSimple(additional)
            default:
                throw KDNACBORError.invalid("unknown CBOR major type")
            }
        }

        mutating func readSimple(_ additional: UInt8) throws -> Any {
            switch additional {
            case 20: return false
            case 21: return true
            case 22: return NSNull()
            case 26:
                let raw = UInt32(try readUnsigned(bytes: 4))
                return NSNumber(value: Float(bitPattern: raw))
            case 27:
                return NSNumber(value: Double(bitPattern: try readUnsigned(bytes: 8)))
            default:
                throw KDNACBORError.unsupported("unsupported CBOR simple value \(additional)")
            }
        }

        mutating func readLength(_ additional: UInt8) throws -> UInt64 {
            switch additional {
            case 0...23: return UInt64(additional)
            case 24: return try readUnsigned(bytes: 1)
            case 25: return try readUnsigned(bytes: 2)
            case 26: return try readUnsigned(bytes: 4)
            case 27: return try readUnsigned(bytes: 8)
            case 31: throw KDNACBORError.unsupported("indefinite-length CBOR is not supported")
            default: throw KDNACBORError.invalid("invalid CBOR additional information")
            }
        }

        mutating func readUnsigned(bytes count: Int) throws -> UInt64 {
            var value: UInt64 = 0
            for byte in try readBytes(count: count) {
                value = (value << 8) | UInt64(byte)
            }
            return value
        }

        mutating func readByte() throws -> UInt8 {
            guard offset < bytes.count else { throw KDNACBORError.truncated }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func readBytes(count: Int) throws -> [UInt8] {
            guard count >= 0, offset + count <= bytes.count else {
                throw KDNACBORError.truncated
            }
            defer { offset += count }
            return Array(bytes[offset..<(offset + count)])
        }
    }
}
