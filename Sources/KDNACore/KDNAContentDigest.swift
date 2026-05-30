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
//   - mimetype: uses literal "application/vnd.aikdna.kdna+zip"

import Foundation
import CryptoKit

public class KDNAContentDigest {

    /// Compute the canonical content digest for a .kdna asset.
    public static func compute(asset: KDNAAsset, reader: KDNAAssetReader = KDNAAssetReader()) -> String {
        let allEntries = reader.listEntries(asset: asset)
        let excluded: Set<String> = [".DS_Store", "signature.json", "build-receipt.json"]

        var parts: [String] = []
        for name in allEntries.sorted() {
            if excluded.contains(name) { continue }
            if name.hasPrefix("reports/") { continue }

            guard let data = try? reader.readEntry(asset: asset, name: name) else { continue }

            let content = name == "mimetype"
                ? "application/vnd.aikdna.kdna+zip"
                : String(data: data, encoding: .utf8) ?? ""

            let hashInput: Data
            if name.hasSuffix(".json") {
                let canonical = canonicalizeJSON(name: name, content: content)
                hashInput = Data(canonical.utf8)
            } else {
                hashInput = Data(content.utf8)
            }

            let hash = SHA256.hash(data: hashInput).compactMap { String(format: "%02x", $0) }.joined()
            parts.append("\(name):\(hash)")
        }

        let payload = parts.joined(separator: "\n")
        let digest = SHA256.hash(data: Data(payload.utf8)).compactMap { String(format: "%02x", $0) }.joined()
        return "sha256:\(digest)"
    }

    /// Compute content digest from a dictionary of filename → content (for export side).
    public static func compute(files: [String: String]) -> String {
        let excluded: Set<String> = ["signature.json", ".DS_Store", "build-receipt.json"]

        var parts: [String] = []
        for name in files.keys.sorted() {
            if excluded.contains(name) { continue }
            if name.hasPrefix("reports/") { continue }

            let contentFromFiles: String = {
                var c = files[name] ?? ""
                if name == "mimetype" { c = "application/vnd.aikdna.kdna+zip" }
                return c
            }()

            let hashInput: Data
            if name.hasSuffix(".json") {
                let canonical = canonicalizeJSON(name: name, content: contentFromFiles)
                hashInput = Data(canonical.utf8)
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
        guard let data = content.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return content }

        var copy = obj
        if name == "kdna.json" {
            copy.removeValue(forKey: "signature")
            copy.removeValue(forKey: "asset_digest")
            copy.removeValue(forKey: "container_sha256")
            copy.removeValue(forKey: "content_digest")
            if var authoring = copy["authoring"] as? [String: Any] {
                authoring.removeValue(forKey: "content_digest")
                copy["authoring"] = authoring
            }
        }

        return stableStringify(copy)
    }

    // MARK: - Stable Stringify

    /// Lexicographically-sorted key canonical JSON (no whitespace).
    /// Matches the JS stableStringify behavior exactly.
    public static func stableStringify(_ value: Any) -> String {
        if let arr = value as? [Any] {
            return "[" + arr.map { stableStringify($0) }.joined(separator: ",") + "]"
        }
        if let dict = value as? [String: Any] {
            let inner = dict.keys.sorted().map { key in
                let val = dict[key]!
                return "\"\(key)\":" + stableStringify(val)
            }.joined(separator: ",")
            return "{" + inner + "}"
        }
        if let str = value as? String {
            // Minimal JSON string escaping
            var escaped = str
            escaped = escaped.replacingOccurrences(of: "\\", with: "\\\\")
            escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
            escaped = escaped.replacingOccurrences(of: "\n", with: "\\n")
            escaped = escaped.replacingOccurrences(of: "\r", with: "\\r")
            escaped = escaped.replacingOccurrences(of: "\t", with: "\\t")
            return "\"\(escaped)\""
        }
        if let num = value as? NSNumber {
            // Check for boolean (NSNumber wraps booleans as __NSCFBoolean)
            let typeID = CFGetTypeID(num as CFTypeRef)
            if typeID == CFBooleanGetTypeID() {
                return num.boolValue ? "true" : "false"
            }
            let d = num.doubleValue
            if d == floor(d) && d.isFinite {
                return String(Int64(d))
            }
            return String(d)
        }
        if value is NSNull { return "null" }
        if let bool = value as? Bool { return bool ? "true" : "false" }
        return "\"\(value)\""
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
            .sorted()
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
            .sorted()
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
