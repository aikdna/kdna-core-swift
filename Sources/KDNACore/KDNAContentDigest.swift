//  KDNACore — Canonical content digest computation
//
//  Aligned with @aikdna/kdna-core/src/asset-reader.js buildContentDigest()
//  and @aikdna/kdna-studio-core/src/compile/index.js computeContentDigest()
//
//  Rules:
//   - path:sha256 format, newline-joined, SHA256 of the result
//   - Excludes: .DS_Store, signature.json, build-receipt.json, reports/*
//   - kdna.json: strips signature, asset_digest, container_sha256, content_digest, authoring.content_digest
//   - All JSON entries: stable-sorted key canonicalization
//   - mimetype: uses the literal media type stored in the asset

import Foundation
import CryptoKit

public enum KDNAContentDigestError: Error, LocalizedError {
    case invalidJSON(entry: String)

    public var errorDescription: String? {
        switch self {
        case .invalidJSON(let entry):
            return "\(entry): invalid JSON"
        }
    }
}

public class KDNAContentDigest {

    /// Compatibility wrapper for callers that cannot yet adopt a throwing API.
    /// Invalid JSON returns a non-digest sentinel rather than silently hashing a
    /// representation that differs from the JavaScript Core.
    @available(*, deprecated, message: "Use computeValidated(asset:reader:) to handle invalid JSON explicitly")
    public static func compute(asset: KDNAAsset, reader: KDNAAssetReader = KDNAAssetReader()) -> String {
        (try? computeValidated(asset: asset, reader: reader)) ?? "invalid:content-digest-input"
    }

    /// Compute the canonical content digest for a .kdna asset.
    public static func computeValidated(
        asset: KDNAAsset,
        reader: KDNAAssetReader = KDNAAssetReader()
    ) throws -> String {
        let allEntries = reader.listEntries(asset: asset)
        let excluded: Set<String> = [".DS_Store", "signature.json", "build-receipt.json"]

        var parts: [String] = []
        for name in allEntries.sorted(by: utf8PathLess) {
            if excluded.contains(name) { continue }
            if name.hasPrefix("reports/") { continue }

            let data = try reader.readEntry(asset: asset, name: name)

            let hashInput: Data
            if name.lowercased().hasSuffix(".json") {
                hashInput = try canonicalizeJSONData(name: name, data: data)
            } else {
                // Non-JSON entries are byte strings. Decoding and re-encoding
                // them as UTF-8 corrupts binary CBOR/encrypted payloads and
                // previously collapsed invalid UTF-8 to an empty byte string.
                hashInput = data
            }

            let hash = SHA256.hash(data: hashInput).compactMap { String(format: "%02x", $0) }.joined()
            parts.append("\(name):\(hash)")
        }

        let payload = parts.joined(separator: "\n")
        let digest = SHA256.hash(data: Data(payload.utf8)).compactMap { String(format: "%02x", $0) }.joined()
        return "sha256:\(digest)"
    }

    /// Compatibility wrapper for string-backed producer inputs.
    @available(*, deprecated, message: "Use computeValidated(files:) to handle invalid JSON explicitly")
    public static func compute(files: [String: String]) -> String {
        (try? computeValidated(files: files)) ?? "invalid:content-digest-input"
    }

    /// Compute content digest from a dictionary of filename → content (for export side).
    public static func computeValidated(files: [String: String]) throws -> String {
        let excluded: Set<String> = ["signature.json", ".DS_Store", "build-receipt.json"]

        var parts: [String] = []
        for name in files.keys.sorted(by: utf8PathLess) {
            if excluded.contains(name) { continue }
            if name.hasPrefix("reports/") { continue }

            let contentFromFiles = files[name] ?? ""

            let hashInput: Data
            if name.lowercased().hasSuffix(".json") {
                hashInput = try canonicalizeJSONData(
                    name: name,
                    data: Data(contentFromFiles.utf8)
                )
            } else {
                hashInput = Data(contentFromFiles.utf8)
            }

            let hash = SHA256.hash(data: hashInput).compactMap { String(format: "%02x", $0) }.joined()
            parts.append("\(name):\(hash)")
        }

        let payload = parts.joined(separator: "\n")
        let digest = SHA256.hash(data: Data(payload.utf8)).compactMap { String(format: "%02x", $0) }.joined()
        return "sha256:\(digest)"
    }

    // MARK: - Canonical JSON

    /// Produce stable-sorted canonical JSON for digest computation.
    /// For kdna.json, strips self-referencing digest fields.
    public static func canonicalizeJSON(name: String, content: String) -> String {
        guard let canonical = try? canonicalizeJSONData(name: name, data: Data(content.utf8)) else {
            return "invalid:json"
        }
        return String(decoding: canonical, as: UTF8.self)
    }

    private static func canonicalizeJSONData(name: String, data: Data) throws -> Data {
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        } catch {
            throw KDNAContentDigestError.invalidJSON(entry: name)
        }

        let canonicalValue: Any
        if name == "kdna.json", let manifest = value as? [String: Any] {
            canonicalValue = manifestForDigest(manifest)
        } else {
            canonicalValue = value
        }
        return Data(stableStringify(canonicalValue).utf8)
    }

    // MARK: - Stable Stringify

    /// Lexicographically-sorted key canonical JSON (no whitespace).
    /// Matches the JS stableStringify behavior exactly.
    public static func stableStringify(_ value: Any) -> String {
        if let arr = value as? [Any] {
            return "[" + arr.map { stableStringify($0) }.joined(separator: ",") + "]"
        }
        if let dict = value as? [String: Any] {
            let inner = dict.keys.sorted(by: jsLexicographicLess).map { key in
                let val = dict[key]!
                return jsonString(key) + ":" + stableStringify(val)
            }.joined(separator: ",")
            return "{" + inner + "}"
        }
        if let str = value as? String {
            return jsonString(str)
        }
        if let num = value as? NSNumber {
            // Check for boolean (NSNumber wraps booleans as __NSCFBoolean)
            let typeID = CFGetTypeID(num as CFTypeRef)
            if typeID == CFBooleanGetTypeID() {
                return num.boolValue ? "true" : "false"
            }
            return jsonNumber(num.doubleValue)
        }
        if value is NSNull { return "null" }
        if let bool = value as? Bool { return bool ? "true" : "false" }
        return "\"\(value)\""
    }

    /// Match JSON.stringify string escaping for valid Swift strings.
    private static func jsonString(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0A: result += "\\n"
            case 0x0C: result += "\\f"
            case 0x0D: result += "\\r"
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x00...0x1F:
                result += String(format: "\\u%04x", scalar.value)
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        result += "\""
        return result
    }

    /// Render a Foundation JSON number with JavaScript JSON.stringify's
    /// decimal/scientific thresholds and exponent spelling.
    private static func jsonNumber(_ value: Double) -> String {
        guard value.isFinite else { return "null" }
        if value == 0 { return "0" }

        let raw = String(value).lowercased()
        guard let exponentMarker = raw.firstIndex(of: "e") else {
            return raw.hasSuffix(".0") ? String(raw.dropLast(2)) : raw
        }

        let mantissa = String(raw[..<exponentMarker])
        let exponentText = String(raw[raw.index(after: exponentMarker)...])
        guard let exponent = Int(exponentText) else { return raw }

        let magnitude = abs(value)
        if magnitude >= 1e-6 && magnitude < 1e21 {
            return expandScientific(mantissa: mantissa, exponent: exponent)
        }

        let normalizedMantissa = mantissa.hasSuffix(".0") ? String(mantissa.dropLast(2)) : mantissa
        let sign = exponent >= 0 ? "+" : "-"
        return "\(normalizedMantissa)e\(sign)\(abs(exponent))"
    }

    private static func expandScientific(mantissa: String, exponent: Int) -> String {
        let negative = mantissa.hasPrefix("-")
        let unsigned = negative ? String(mantissa.dropFirst()) : mantissa
        let components = unsigned.split(separator: ".", omittingEmptySubsequences: false)
        let integerDigits = String(components[0])
        let fractionalDigits = components.count == 2 ? String(components[1]) : ""
        let digits = integerDigits + fractionalDigits
        let decimalPosition = integerDigits.count + exponent

        let expanded: String
        if decimalPosition <= 0 {
            expanded = "0." + String(repeating: "0", count: -decimalPosition) + digits
        } else if decimalPosition >= digits.count {
            expanded = digits + String(repeating: "0", count: decimalPosition - digits.count)
        } else {
            let split = digits.index(digits.startIndex, offsetBy: decimalPosition)
            expanded = String(digits[..<split]) + "." + String(digits[split...])
        }
        return negative ? "-" + expanded : expanded
    }

    /// JavaScript Array#sort without a comparator orders UTF-16 code units.
    /// Swift's native String ordering is Unicode-aware and differs for some
    /// non-BMP keys and entry paths.
    private static func jsLexicographicLess(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf16.lexicographicallyPrecedes(rhs.utf16)
    }

    /// Protocol entry paths are ordered by their UTF-8 bytes. This is distinct
    /// from RFC 8785 object-key ordering, which compares UTF-16 code units.
    static func utf8PathLess(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
    }

    // MARK: - Manifest Templates

    /// Strip self-referencing fields from manifest for content_digest computation.
    /// Includes stripping authoring.content_digest (aligns with JS canonicalizeJson fix).
    public static func manifestForDigest(_ manifest: [String: Any]) -> [String: Any] {
        var copy = manifest
        copy.removeValue(forKey: "signature")
        copy.removeValue(forKey: "asset_digest")
        copy.removeValue(forKey: "container_sha256")
        copy.removeValue(forKey: "content_digest")
        copy.removeValue(forKey: "_source")
        if var authoring = copy["authoring"] as? [String: Any] {
            authoring.removeValue(forKey: "content_digest")
            copy["authoring"] = authoring
        }
        return copy
    }

    /// Strip signature fields from manifest for signing payload computation.
    public static func manifestForSignature(_ manifest: [String: Any]) -> [String: Any] {
        var copy = manifest
        copy.removeValue(forKey: "signature")
        copy.removeValue(forKey: "_source")
        return copy
    }

    // MARK: - Signing Payload

    /// Build canonical signing payload: sorted JSON entries → name:sha256 lines.
    public static func canonicalSigningPayload(entries: [String: Data]) -> String {
        entries.keys
            .filter { $0.lowercased().hasSuffix(".json") && $0 != "signature.json" }
            .sorted(by: utf8PathLess)
            .map { name in
                let payloadData: Data
                if name == "kdna.json", let obj = try? JSONSerialization.jsonObject(with: entries[name] ?? Data()) as? [String: Any] {
                    payloadData = Data(stableStringify(manifestForSignature(obj)).utf8)
                } else {
                    payloadData = entries[name] ?? Data()
                }
                return "\(name):\(KDNACrypto.sha256Hex(payloadData))"
            }
            .joined(separator: "\n")
    }

    /// Legacy asset content digest from raw entry data (for app compatibility).
    /// Prefer `compute(asset:)` or `compute(files:)` for new code.
    public static func assetContentDigest(entries: [String: Data]) -> String {
        let excluded: Set<String> = [".DS_Store", "signature.json", "build-receipt.json"]
        let parts = entries.keys
            .filter { !excluded.contains($0) }
            .filter { !$0.hasPrefix("reports/") }
            .sorted(by: utf8PathLess)
            .map { name in
                let digestData: Data
                if name == "kdna.json", let obj = try? JSONSerialization.jsonObject(with: entries[name] ?? Data()) as? [String: Any] {
                    digestData = Data(stableStringify(manifestForDigest(obj)).utf8)
                } else {
                    digestData = entries[name] ?? Data()
                }
                return "\(name):\(KDNACrypto.sha256Hex(digestData))"
            }
            .joined(separator: "\n")
        return "sha256:\(KDNACrypto.sha256Hex(Data(parts.utf8)))"
    }
}
