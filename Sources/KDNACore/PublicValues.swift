import Foundation
import CryptoKit

/// Exact Unicode scalar bytes. Swift String's normalization-aware equality is
/// deliberately not used for public identifiers, names, or JSON member keys.
public struct KDNAKey: Hashable {
    public let text: String
    public init(_ text: String) { self.text = text }
    public static func == (a: Self, b: Self) -> Bool { a.text.utf8.elementsEqual(b.text.utf8) }
    public func hash(into hasher: inout Hasher) { for byte in text.utf8 { hasher.combine(byte) } }
}
extension KDNAKey: ExpressibleByStringLiteral { public init(stringLiteral value: String) { self.init(value) } }

public indirect enum KDNAValue: Equatable {
    case null, bool(Bool), number(Double), string(String), array([KDNAValue]), object([KDNAKey: KDNAValue])
    public static func == (a: Self, b: Self) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.number(x), .number(y)): return x == y
        case let (.string(x), .string(y)): return KDNAKey(x) == KDNAKey(y)
        case let (.array(x), .array(y)): return x == y
        case let (.object(x), .object(y)): return x == y
        default: return false
        }
    }
    public var text: String { if case .string(let x) = self { return x }; return "" }
    public var list: [Self] { if case .array(let x) = self { return x }; return [] }
    public var fields: [KDNAKey: Self] { if case .object(let x) = self { return x }; return [:] }
    public var numeric: Double { if case .number(let x) = self { return x }; return .nan }
    public var boolean: Bool { if case .bool(let x) = self { return x }; return false }
    public func has(_ key: String) -> Bool { fields[KDNAKey(key)] != nil }
    public subscript(_ key: String) -> Self {
        get { fields[KDNAKey(key)] ?? .null }
        set { var object = fields; object[KDNAKey(key)] = newValue; self = .object(object) }
    }
    public mutating func remove(_ key: String) { var object = fields; object.removeValue(forKey: KDNAKey(key)); self = .object(object) }
}

extension KDNAValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByStringLiteral,
                     ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(arrayLiteral elements: Self...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, Self)...) { self = .object(Dictionary(elements.map { (KDNAKey($0.0), $0.1) }, uniquingKeysWith: { _, b in b })) }
}

typealias J = KDNAValue
struct PublicFailure: Error {
    let code: String
    let componentFailure: J
    init(_ code: String = "READ_CORE_INVALID", componentFailure: J = nil) { self.code = code; self.componentFailure = componentFailure }
}
func demand(_ condition: Bool, _ code: String = "READ_CORE_INVALID") throws { if !condition { throw PublicFailure(code) } }
func exact(_ a: String, _ b: String) -> Bool { KDNAKey(a) == KDNAKey(b) }
func scalar(_ value: String, maximum: Int = 1048576, controls: Bool = true) -> Bool {
    value.utf8.count <= maximum && (controls || value.unicodeScalars.allSatisfy { $0.value > 31 && !(127...159).contains($0.value) })
}
func identifier(_ value: J) -> Bool { if case .string(let text) = value { return !text.isEmpty && scalar(text, maximum: 256, controls: false) }; return false }
func validEntry(_ name: String) -> Bool {
    !name.isEmpty && scalar(name, maximum: 4096, controls: false) && !name.contains("\\") && !name.hasPrefix("/") &&
    name.range(of: "^[A-Za-z]:", options: .regularExpression) == nil &&
    name.split(separator: "/", omittingEmptySubsequences: false).allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
}
func isUInt(_ value: J) -> Bool { let n = value.numeric; return n.isFinite && n >= 0 && n <= 9007199254740991 && n.rounded(.towardZero) == n }
func sha(_ data: Data) -> String { "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

public enum KDNAJSON {
    public static func parse(_ data: Data) throws -> KDNAValue {
        let bytes = Array(data)
        guard String(bytes: bytes, encoding: .utf8) != nil else { throw PublicFailure("READ_CORE_INVALID") }
        // Match the accepted UTF8 decoder's initial signature handling. No
        // replacement or Unicode normalization is applied to the input.
        let signatureLength = bytes.starts(with: [0xef, 0xbb, 0xbf]) ? 3 : 0
        var parser = StrictJSON(bytes: Array(bytes.dropFirst(signatureLength)))
        return try parser.parse()
    }
    public static func canonical(_ value: KDNAValue) throws -> Data {
        var count = 0
        func encode(_ v: J, _ depth: Int) throws -> String {
            count += 1
            try demand(depth <= 64 && count <= 100000, "READ_INPUT_INVALID")
            switch v {
            case .null: return "null"
            case .bool(let x): return x ? "true" : "false"
            case .number(let x): return try numberText(x)
            case .string(let x):
                try demand(scalar(x), "READ_INPUT_INVALID")
                return quote(x)
            case .array(let x):
                try demand(x.count <= 10000, "READ_INPUT_INVALID")
                return "[" + (try x.map { try encode($0, depth + 1) }).joined(separator: ",") + "]"
            case .object(let x):
                let keys = x.keys.sorted { $0.text.utf16.lexicographicallyPrecedes($1.text.utf16) }
                return "{" + (try keys.map { key in
                    try demand(scalar(key.text), "READ_INPUT_INVALID")
                    return quote(key.text) + ":" + (try encode(x[key]!, depth + 1))
                }).joined(separator: ",") + "}"
            }
        }
        return Data(try encode(value, 0).utf8)
    }
    static func quote(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 34: out += "\\\""
            case 92: out += "\\\\"
            case 8: out += "\\b"
            case 9: out += "\\t"
            case 10: out += "\\n"
            case 12: out += "\\f"
            case 13: out += "\\r"
            case 0...31: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
    static func numberText(_ value: Double) throws -> String {
        try demand(value.isFinite, "READ_INPUT_INVALID")
        if value == 0 { return "0" }
        let parts = String(abs(value)).lowercased().split(separator: "e", omittingEmptySubsequences: false)
        let exponent = parts.count == 2 ? Int(parts[1])! : 0
        let decimal = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        let whole = String(decimal[0]), fraction = decimal.count == 2 ? String(decimal[1]) : ""
        var digits = Array((whole + fraction).drop(while: { $0 == "0" }))
        var point = whole.count + exponent
        if whole == "0" { point = -fraction.prefix(while: { $0 == "0" }).count + exponent }
        while digits.count > 1 && digits.last == "0" { digits.removeLast() }
        let out: String
        if point > 0 && point <= 21 {
            if point < digits.count { out = String(digits.prefix(point)) + "." + String(digits.dropFirst(point)) }
            else { out = String(digits) + String(repeating: "0", count: point - digits.count) }
        } else if point > -6 && point <= 0 {
            out = "0." + String(repeating: "0", count: -point) + String(digits)
        } else {
            let power = point - 1
            out = String(digits[0]) + (digits.count > 1 ? "." + String(digits.dropFirst()) : "") + "e" + (power >= 0 ? "+" : "-") + String(abs(power))
        }
        return (value < 0 ? "-" : "") + out
    }
}

private struct StrictJSON {
    func syntax(_ condition: Bool, _ code: String = "READ_INPUT_INVALID") throws { try demand(condition, code) }
    let bytes: [UInt8]
    var at = 0
    var count = 0
    mutating func whitespace() { while at < bytes.count && [32, 9, 10, 13].contains(bytes[at]) { at += 1 } }
    mutating func parse() throws -> J {
        let value = try value(0); whitespace(); try syntax(at == bytes.count)
        return value
    }
    mutating func string() throws -> String {
        try syntax(at < bytes.count && bytes[at] == 34); at += 1
        var result = String.UnicodeScalarView()
        var raw: [UInt8] = []
        func decoded(_ bytes: [UInt8]) throws -> String { guard let s = String(bytes: bytes, encoding: .utf8) else { throw PublicFailure() }; return s }
        while at < bytes.count {
            let b = bytes[at]; at += 1
            if b == 34 {
                result.append(contentsOf: try decoded(raw).unicodeScalars)
                let text = String(result); try syntax(scalar(text), "READ_INPUT_INVALID"); return text
            }
            try syntax(b >= 32)
            if b != 92 { raw.append(b); continue }
            result.append(contentsOf: try decoded(raw).unicodeScalars); raw = []
            try syntax(at < bytes.count)
            let escape = bytes[at]; at += 1
            if let value: UInt32 = [34:34, 92:92, 47:47, 98:8, 102:12, 110:10, 114:13, 116:9][Int(escape)] {
                result.append(Unicode.Scalar(value)!); continue
            }
            try syntax(escape == 117, "READ_CORE_INVALID")
            var n = try hex()
            if (0xd800...0xdbff).contains(n) {
                try syntax(at + 2 <= bytes.count && bytes[at] == 92 && bytes[at + 1] == 117, "READ_INPUT_INVALID"); at += 2
                let low = try hex(); try syntax((0xdc00...0xdfff).contains(low), "READ_INPUT_INVALID")
                n = 0x10000 + (n - 0xd800) * 1024 + low - 0xdc00
            } else { try syntax(!(0xdc00...0xdfff).contains(n), "READ_INPUT_INVALID") }
            guard let scalar = Unicode.Scalar(n) else { throw PublicFailure("READ_INPUT_INVALID") }
            result.append(scalar)
        }
        throw PublicFailure("READ_INPUT_INVALID")
    }
    mutating func hex() throws -> UInt32 {
        try syntax(at + 4 <= bytes.count, "READ_CORE_INVALID")
        let text = String(bytes: bytes[at..<at + 4], encoding: .ascii); at += 4
        guard let text, let n = UInt32(text, radix: 16) else { throw PublicFailure() }; return n
    }
    mutating func value(_ depth: Int) throws -> J {
        count += 1; try syntax(depth <= 64 && count <= 100000, "READ_INPUT_INVALID"); whitespace()
        try syntax(at < bytes.count)
        let b = bytes[at]
        if b == 34 { return .string(try string()) }
        if b == 123 {
            at += 1; whitespace(); var result: [KDNAKey:J] = [:]
            if at < bytes.count && bytes[at] == 125 { at += 1; return .object(result) }
            while true {
                whitespace(); let key = KDNAKey(try string()); try syntax(result[key] == nil, "READ_INPUT_INVALID")
                whitespace(); try syntax(at < bytes.count && bytes[at] == 58); at += 1
                result[key] = try value(depth + 1); whitespace(); try syntax(at < bytes.count)
                let end = bytes[at]; at += 1
                if end == 125 { return .object(result) }; try syntax(end == 44)
            }
        }
        if b == 91 {
            at += 1; whitespace(); var result: [J] = []
            if at < bytes.count && bytes[at] == 93 { at += 1; return .array(result) }
            while true {
                try syntax(result.count < 10000, "READ_INPUT_INVALID"); result.append(try value(depth + 1)); whitespace(); try syntax(at < bytes.count)
                let end = bytes[at]; at += 1
                if end == 93 { return .array(result) }; try syntax(end == 44)
            }
        }
        let tokens: [(String,J)] = [("true", true), ("false", false), ("null", nil)]
        for (token, v) in tokens {
            let encoded = Array(token.utf8)
            if at + encoded.count <= bytes.count && bytes[at..<at + encoded.count].elementsEqual(encoded) { at += encoded.count; return v }
        }
        let start = at
        if bytes[at] == 45 { at += 1 }
        try syntax(at < bytes.count)
        if bytes[at] == 48 { at += 1 }
        else { try syntax((49...57).contains(bytes[at])); while at < bytes.count && (48...57).contains(bytes[at]) { at += 1 } }
        if at < bytes.count && bytes[at] == 46 {
            at += 1; let start = at
            while at < bytes.count && (48...57).contains(bytes[at]) { at += 1 }; try syntax(at > start)
        }
        if at < bytes.count && (bytes[at] == 101 || bytes[at] == 69) {
            at += 1; if at < bytes.count && (bytes[at] == 43 || bytes[at] == 45) { at += 1 }
            let start = at; while at < bytes.count && (48...57).contains(bytes[at]) { at += 1 }; try syntax(at > start)
        }
        guard let text = String(bytes: bytes[start..<at], encoding: .ascii), let n = Double(text) else { throw PublicFailure("READ_INPUT_INVALID") }
        try syntax(n.isFinite, "READ_INPUT_INVALID"); return .number(n)
    }
}
