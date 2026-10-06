import Foundation
import CryptoKit

// The diagnostic structural scanner (section-structure-scanner.js,
// @aikdna/kdna-core@0.36.0): a definite CBOR walk that reads only the
// retained registration paths, skips body text without validating or hashing
// it, and records every read and skip with its purpose. Not full-frame
// validation — the codes are verbatim (SCAN_*), and the accounting
// (read_bytes / skipped_text_bytes / per-read offsets) is observable.
enum SectionStructureScanner {
    static let skippedText: J = ["scan_observation": "text_bytes_not_read"]
    struct Skip { let offset: Int; let length: Int }
    struct Read { let offset: Int; let length: Int }
    struct Result {
        let partial: J
        let reads: [Read]
        let readBytes: Int
        let skippedTextBytes: Int
    }
    private final class Walker {
        let length: Int
        let interpretationInputs: Bool
        let read: (Int, Int, String) throws -> [UInt8]
        var offset = 0
        var reads: [Read] = []
        var readBytes = 0
        var skips: [Skip] = []
        var skippedTextBytes = 0
        init(_ length: Int, _ interpretationInputs: Bool, _ read: @escaping (Int, Int, String) throws -> [UInt8]) {
            self.length = length; self.interpretationInputs = interpretationInputs; self.read = read
        }
        func take(_ n: Int, _ purpose: String) throws -> [UInt8] {
            try need(n >= 0 && offset + n <= length, "SCAN_RANGE")
            let start = offset
            offset += n
            if n == 0 { return [] }
            let bytes = try read(start, n, purpose)
            try need(bytes.count == n, "SCAN_SHORT")
            reads.append(Read(offset: start, length: n))
            readBytes += n
            return bytes
        }
        func skip(_ n: Int) throws {
            try need(n >= 0 && offset + n <= length, "SCAN_RANGE")
            skips.append(Skip(offset: offset, length: n))
            skippedTextBytes += n
            offset += n
        }
        func need(_ condition: Bool, _ code: String) throws { if !condition { throw PublicFailure(code) } }
        func argument(_ info: Int) throws -> Int {
            if info < 24 { return info }
            try need(info >= 24 && info <= 27, "SCAN_INDEFINITE_OR_RESERVED")
            let bytes = try take(1 << (info - 24), "cbor_argument")
            switch info {
            case 24: return Int(bytes[0])
            case 25: return Int(bytes[0]) << 8 | Int(bytes[1])
            case 26: return Int(bytes[0]) << 24 | Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
            default:
                var value: UInt64 = 0
                for byte in bytes { value = value << 8 | UInt64(byte) }
                // The JS guard is Number.isSafeInteger; the exact-representable
                // Double case above the safe range is accepted there too, but
                // every collection/string length that passes is safe.
                guard value <= 9007199254740991 else { throw PublicFailure("SCAN_LENGTH_OR_INTEGER_RANGE") }
                return Int(value)
            }
        }
        func isEnvelope(_ path: [PathElement]) -> Bool {
            guard path.count == 3, path[0] == .key("records"), case .index = path[1] else { return false }
            if case .key(let last) = path[2], ["value", "method_interpretation", "static_policy_interpretation"].contains(last) { return false }
            return true
        }
        func retained(_ path: [PathElement], _ force: Bool) -> Bool {
            if interpretationInputs, path.count >= 3, path[0] == .key("records"), path[1].isIndex, path[2] == .key("value") {
                if path.count == 4, case .key(let field) = path[3],
                   ["method", "extensions", "result_contract", "formation_rule", "parent_ref", "lifecycle"].contains(field) { return true }
                if case .key(let last) = path[path.count - 1], ["extension", "extensions"].contains(last) { return true }
            }
            if force || isEnvelope(path) { return true }
            if path.count == 1, case .key(let only) = path[0], ["kind", "section_id"].contains(only) { return true }
            if path.count >= 3, path[0] == .key("records"), path[2] == .key("value"), case .key(let last) = path[path.count - 1] {
                return ["id", "kind", "asset_uid", "owner_ref", "state"].contains(last)
            }
            return false
        }
        func value(_ depth: Int, _ path: [PathElement], _ forceIn: Bool, _ key: Bool) throws -> J {
            try need(depth <= 64, "SCAN_DEPTH")
            let initial = try take(1, "cbor_initial")
            let major = Int(initial[0] >> 5), info = Int(initial[0] & 31)
            let force = retained(path, forceIn)
            if major == 0 || major == 1 {
                if info == 27 {
                    let bytes = try take(8, "cbor_integer")
                    var raw: UInt64 = 0
                    for byte in bytes { raw = raw << 8 | UInt64(byte) }
                    if major == 0 {
                        let d = Double(raw)
                        guard let back = UInt64(exactly: d), back == raw else { throw PublicFailure("SCAN_INTEGER_REPRESENTATION") }
                        return .number(d)
                    }
                    // major 1: the value is -1 - raw; exact iff the Double
                    // round-trip reproduces it (raw = u64 max gives -2^64).
                    let negated = -Double(raw) - 1
                    if raw == UInt64.max {
                        guard negated == -18446744073709551616.0 else { throw PublicFailure("SCAN_INTEGER_REPRESENTATION") }
                    } else {
                        guard let backMag = UInt64(exactly: -negated), backMag == raw + 1 else { throw PublicFailure("SCAN_INTEGER_REPRESENTATION") }
                    }
                    return .number(negated)
                }
                let n = try argument(info)
                return .number(Double(major == 0 ? n : -1 - n))
            }
            if major == 2 || major == 3 {
                try need(major == 3, "SCAN_BYTE_STRING")
                let n = try argument(info)
                try need(n <= 1048576, "SCAN_STRING_LIMIT")
                if !force && !key { try skip(n); return SectionStructureScanner.skippedText }
                let bytes = try take(n, key ? "map_key" : "binding_string")
                // The released decoder is fatal UTF-8 with ignoreBOM:true,
                // i.e. a leading BOM stays in the text — and is rejected here.
                guard let text = String(bytes: bytes, encoding: .utf8) else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
                try need(text.unicodeScalars.first?.value != 0xFEFF, "SCAN_LEADING_BOM")
                return .string(text)
            }
            if major == 4 || major == 5 {
                let n = try argument(info)
                try need(n <= 10000, "SCAN_COLLECTION_LIMIT")
                if major == 4 {
                    var items: [J] = []
                    for i in 0..<n { items.append(try value(depth + 1, path + [.index(i)], force, false)) }
                    return .array(items)
                }
                var object: J = [:]
                var keys = Set<String>()
                for _ in 0..<n {
                    let k = try value(depth + 1, path + [.key("<key>")], false, true)
                    guard case .string(let name) = k, !keys.contains(name) else { throw PublicFailure("SCAN_MAP_KEY") }
                    keys.insert(name)
                    object[name] = try value(depth + 1, path + [.key(name)], force, false)
                }
                return object
            }
            if major == 7 {
                if info == 20 { return .bool(false) }
                if info == 21 { return .bool(true) }
                if info == 22 { return .null }
                try need(info >= 25 && info <= 27, "SCAN_SIMPLE")
                let bytes = try take(1 << (info - 24), "cbor_float")
                let n: Double
                if info == 25 {
                    let x = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
                    let sign = (x & 0x8000) != 0 ? -1.0 : 1.0
                    let exponent = Int((x >> 10) & 31), fraction = Double(x & 1023)
                    let half = exponent == 0 ? pow(2, -14) * fraction / 1024
                        : exponent == 31 ? Double.infinity
                        : pow(2, Double(exponent - 15)) * (1 + fraction / 1024)
                    return try finite(sign * half)
                } else if info == 26 {
                    var raw: UInt32 = 0
                    for byte in bytes { raw = raw << 8 | UInt32(byte) }
                    n = Double(Float(bitPattern: raw))
                } else {
                    var raw: UInt64 = 0
                    for byte in bytes { raw = raw << 8 | UInt64(byte) }
                    n = Double(bitPattern: raw)
                }
                return try finite(n)
            }
            try need(false, "SCAN_TAG_OR_MAJOR")
            throw PublicFailure("SCAN_TAG_OR_MAJOR")
        }
        func finite(_ value: Double) throws -> J {
            try need(value.isFinite, "SCAN_NONFINITE")
            return .number(value)
        }
    }
    enum PathElement: Equatable {
        case key(String), index(Int)
        var isIndex: Bool { if case .index = self { return true }; return false }
    }
    static func scanFrame(_ length: Int, _ interpretationInputs: Bool = false, _ read: @escaping (Int, Int, String) throws -> [UInt8]) throws -> Result {
        let walker = Walker(length, interpretationInputs, read)
        let partial = try walker.value(0, [], false, false)
        try walker.need(walker.offset == length, "SCAN_TRAILING_BYTES")
        return Result(partial: partial, reads: walker.reads, readBytes: walker.readBytes, skippedTextBytes: walker.skippedTextBytes)
    }
}
