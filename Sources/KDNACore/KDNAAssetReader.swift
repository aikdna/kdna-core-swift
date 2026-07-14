//  KDNACore — Native .kdna asset reader (ZIP container access)
//
//  Reads .kdna files as PKZIP containers without persistent extraction.
//  Provides open, list, read, and JSON access methods.
//  Aligned with @aikdna/kdna-core/src/asset-reader.js (Node.js)

import Foundation
import CryptoKit
import Compression

public struct KDNAAsset {
    public let path: String
    public let size: Int
    public let assetDigest: String
    let entries: [String: (offset: UInt32, compressedSize: UInt32, uncompressedSize: UInt32, compressionMethod: UInt16)]
    let data: Data
}

public class KDNAAssetReader {
    public static let kdnaMediaType = "application/vnd.kdna.asset"

    public init() {}

    // MARK: - Open

    public func open(url: URL) throws -> KDNAAsset {
        let data = try Data(contentsOf: url)
        return try open(data: data, path: url.path)
    }

    public func open(path: String) throws -> KDNAAsset {
        let url = URL(fileURLWithPath: path)
        return try open(url: url)
    }

    public func open(data: Data, path: String = "") throws -> KDNAAsset {
        let entries = try parseCentralDirectory(data: data)
        let digest = "sha256:" + SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        return KDNAAsset(
            path: path,
            size: data.count,
            assetDigest: digest,
            entries: entries,
            data: data
        )
    }

    // MARK: - Read

    public func readEntry(asset: KDNAAsset, name: String) throws -> Data {
        guard let entry = asset.entries[name] else {
            throw KDNAAssetError.entryNotFound(name)
        }
        let start = Int(entry.offset)
        let size = Int(entry.compressedSize)
        let raw = asset.data.subdata(in: start..<(start + size))

        if entry.compressionMethod == 0 {
            return raw
        } else if entry.compressionMethod == 8 {
            return try inflate(raw, expectedSize: Int(entry.uncompressedSize))
        }
        throw KDNAAssetError.unsupportedCompression(entry.compressionMethod)
    }

    public func readEntry(asset: KDNAAsset, name: String, manifest: KDNAManifest?, decryptEntry: KDNADecryptEntry? = nil) throws -> Data {
        let raw: Data
        do {
            raw = try readEntry(asset: asset, name: name)
        } catch KDNAAssetError.entryNotFound {
            // If the plain entry is missing, try the encrypted suffix
            raw = try readEntry(asset: asset, name: "\(name).encrypted")
        }
        guard let manifest = manifest, let decryptEntry = decryptEntry else { return raw }
        guard manifest.encryption?.encrypted_entries?.contains(name) == true else { return raw }
        return try decryptEntry(asset, manifest, name, raw)
    }

    public func readString(asset: KDNAAsset, name: String) throws -> String {
        let data = try readEntry(asset: asset, name: name)
        return String(data: data, encoding: .utf8) ?? ""
    }

    public func readJSON(asset: KDNAAsset, name: String) throws -> [String: Any]? {
        let data = try readEntry(asset: asset, name: name)
        return try JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    public func readJSON(asset: KDNAAsset, name: String, manifest: KDNAManifest?, decryptEntry: KDNADecryptEntry? = nil) throws -> [String: Any]? {
        let data = try readEntry(asset: asset, name: name, manifest: manifest, decryptEntry: decryptEntry)
        return try JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    public func readManifest(asset: KDNAAsset) throws -> [String: Any]? {
        return try readJSON(asset: asset, name: "kdna.json")
    }

    /// Decode the manifest as a typed KDNAManifest.
    public func decodeManifest(asset: KDNAAsset) throws -> KDNAManifest? {
        guard let data = try? readEntry(asset: asset, name: "kdna.json"),
              let manifest = try? JSONDecoder().decode(KDNAManifest.self, from: data) else {
            return nil
        }
        return manifest
    }

    // MARK: - List

    public func listEntries(asset: KDNAAsset) -> [String] {
        return asset.entries.keys.sorted()
    }

    public func hasEntry(asset: KDNAAsset, name: String) -> Bool {
        return asset.entries[name] != nil
    }

    // MARK: - Verify

    public func verifyMediaType(asset: KDNAAsset) -> Bool {
        guard let data = try? readEntry(asset: asset, name: "mimetype") else { return false }
        let mediaType = String(data: data, encoding: .utf8)
        return mediaType == Self.kdnaMediaType
    }

    public func mediaType(asset: KDNAAsset) -> String? {
        guard let data = try? readEntry(asset: asset, name: "mimetype") else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Verify

    public struct VerifyResult {
        public let ok: Bool
        public let errors: [String]
        public let warnings: [String]
        public let contentDigest: String?
        public let assetDigest: String?
        public let signatureValid: Bool?
    }

    public func verifySync(
        _ asset: KDNAAsset,
        requireDecryption: Bool = false,
        decryptEntry: KDNADecryptEntry? = nil
    ) -> VerifyResult {
        var errors: [String] = []
        let warnings: [String] = []

        if !hasEntry(asset: asset, name: "kdna.json") { errors.append("required entry missing: kdna.json") }
        if !verifyMediaType(asset: asset) { errors.append("invalid or missing mimetype") }
        if !hasEntry(asset: asset, name: "payload.kdnab") { errors.append("required entry missing: payload.kdnab") }

        verifyDeclaredChecksums(asset: asset, errors: &errors)

        if requireDecryption {
            if let manifest = try? decodeManifest(asset: asset),
               let encryptedEntries = manifest.encryption?.encrypted_entries,
               !encryptedEntries.isEmpty {
                if let decryptEntry = decryptEntry {
                    for entryName in encryptedEntries {
                        do {
                            _ = try readEntry(asset: asset, name: entryName, manifest: manifest, decryptEntry: decryptEntry)
                        } catch {
                            errors.append("decryption failed for \(entryName): \(error.localizedDescription)")
                        }
                    }
                } else {
                    errors.append("encrypted entries present but no decryptEntry hook provided")
                }
            }
        }

        let contentDigest: String?
        do {
            contentDigest = try KDNAContentDigest.computeValidated(asset: asset, reader: self)
        } catch {
            contentDigest = nil
            errors.append(error.localizedDescription)
        }
        let assetDigest = asset.assetDigest

        return VerifyResult(
            ok: errors.isEmpty,
            errors: errors,
            warnings: warnings,
            contentDigest: contentDigest,
            assetDigest: assetDigest,
            signatureValid: nil
        )
    }

    private func verifyDeclaredChecksums(asset: KDNAAsset, errors: inout [String]) {
        guard hasEntry(asset: asset, name: "checksums.json") else { return }
        let checksums: [String: Any]
        do {
            let data = try readEntry(asset: asset, name: "checksums.json")
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                errors.append("checksums.json: expected a JSON object")
                return
            }
            checksums = object
        } catch {
            errors.append("checksums.json: invalid JSON")
            return
        }

        if checksums["algorithm"] as? String ?? "sha256" != "sha256" {
            errors.append("checksums.json: unsupported digest algorithm")
        }
        do {
            try KDNAChecksumDigests.validateMetadata(in: checksums)
        } catch {
            errors.append("checksums.json: invalid entry-set metadata")
        }

        let entrySetDigest: String?
        do {
            entrySetDigest = try KDNAChecksumDigests.entrySetDigest(in: checksums)
        } catch {
            errors.append("checksums.json: conflicting or invalid entry-set digest declarations")
            return
        }

        let covered = KDNAChecksumDigests.runtimeCoveredEntries.compactMap { name -> (String, Data)? in
            guard let data = try? readEntry(asset: asset, name: name) else { return nil }
            return (name, data)
        }
        for (key, name) in [("manifest_digest", "kdna.json"), ("payload_digest", "payload.kdnab")] {
            guard let declared = checksums[key] as? String,
                  let data = covered.first(where: { $0.0 == name })?.1 else { continue }
            if declared != "sha256:\(KDNACrypto.sha256Hex(data))" {
                errors.append("checksums.json: \(key) mismatch")
            }
        }
        if let entrySetDigest {
            let combined = covered
                .sorted { $0.0 < $1.0 }
                .map { "\($0.0):\(KDNACrypto.sha256Hex($0.1))" }
                .joined(separator: "\n")
            if entrySetDigest != "sha256:\(KDNACrypto.sha256Hex(Data(combined.utf8)))" {
                errors.append("checksums.json: entry-set digest mismatch")
            }
        }
    }

    // MARK: - ZIP Central Directory Parser

    private func parseCentralDirectory(data: Data) throws -> [String: (UInt32, UInt32, UInt32, UInt16)] {
        // Find end-of-central-directory record
        guard data.count > 22 else { throw KDNAAssetError.invalidZIP }

        var eocdOffset = data.count - 22
        while eocdOffset >= 0 {
            let sig = data.advanced(by: eocdOffset).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            if sig == 0x06054b50 { break }
            eocdOffset -= 1
        }
        guard eocdOffset >= 0 else { throw KDNAAssetError.invalidZIP }

        let eocd = data.advanced(by: eocdOffset)
        let cdOffset = Int(eocd.advanced(by: 16).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
        let cdCount = Int(eocd.advanced(by: 10).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })

        var entries: [String: (UInt32, UInt32, UInt32, UInt16)] = [:]
        var pos = cdOffset

        for _ in 0..<cdCount {
            let cd = data.advanced(by: pos)
            let sig = cd.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            if sig != 0x02014b50 { break }

            let nameLen = Int(cd.advanced(by: 28).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let extraLen = Int(cd.advanced(by: 30).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let commentLen = Int(cd.advanced(by: 32).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let compMethod = cd.advanced(by: 10).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) }
            let compSize = cd.advanced(by: 20).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            let uncompSize = cd.advanced(by: 24).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            let localOffset = cd.advanced(by: 42).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

            let nameData = cd.advanced(by: 46).prefix(nameLen)
            guard let name = String(data: nameData, encoding: .utf8) else { break }

            // Read local header to get actual data offset
            let local = data.advanced(by: Int(localOffset))
            let localNameLen = Int(local.advanced(by: 26).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let localExtraLen = Int(local.advanced(by: 28).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let dataOffset = UInt32(Int(localOffset) + 30 + localNameLen + localExtraLen)

            entries[name] = (dataOffset, compSize, uncompSize, compMethod)

            pos += 46 + nameLen + extraLen + commentLen
        }

        return entries
    }
    // MARK: - Decompression

    private func inflate(_ data: Data, expectedSize: Int) throws -> Data {
        let capacity = max(expectedSize, data.count * 4)
        var outBuffer = Data(count: capacity)
        let result = outBuffer.withUnsafeMutableBytes { dstPtr in
            data.withUnsafeBytes { srcPtr in
                compression_decode_buffer(
                    dstPtr.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    srcPtr.bindMemory(to: UInt8.self).baseAddress!, data.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        guard result > 0 else { throw KDNAAssetError.invalidZIP }
        return outBuffer.prefix(result)
    }
}

// MARK: - Errors

public enum KDNAAssetError: Error, LocalizedError {
    case invalidZIP
    case entryNotFound(String)
    case unsupportedCompression(UInt16)

    public var errorDescription: String? {
        switch self {
        case .invalidZIP: return "Invalid .kdna asset: ZIP structure not recognized"
        case .entryNotFound(let name): return "Entry not found in .kdna asset: \(name)"
        case .unsupportedCompression(let m): return "Unsupported compression method: \(m)"
        }
    }
}
