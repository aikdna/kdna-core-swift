import Foundation

/// Resolves the digest of the integrity-covered entry set declared by
/// `checksums.json`.
///
/// `entry_set_digest` is the unambiguous field name. `asset_digest` remains a
/// deprecated compatibility alias for KDNA 1.0 containers, Runtime Capsule
/// 1.0, and external grant v1. When both fields are present they must agree.
public enum KDNAChecksumDigests {
    public static let runtimeEntrySetProfile = "kdna-runtime-entry-set-v1"
    public static let runtimeCoveredEntries = ["kdna.json", "payload.kdnab"]

    public enum ResolutionError: Error {
        case conflictingEntrySetDigests
        case invalidEntrySetDigestDeclaration
        case invalidDigestProfile
        case invalidCoveredEntries
    }

    public static func validateMetadata(in checksums: [String: Any]) throws {
        if checksums.keys.contains("digest_profile"),
           checksums["digest_profile"] as? String != runtimeEntrySetProfile {
            throw ResolutionError.invalidDigestProfile
        }
        if checksums.keys.contains("covered_entries"),
           checksums["covered_entries"] as? [String] != runtimeCoveredEntries {
            throw ResolutionError.invalidCoveredEntries
        }
    }

    public static func entrySetDigest(in checksums: [String: Any]) throws -> String? {
        if checksums.keys.contains("entry_set_digest"),
           checksums["entry_set_digest"] as? String == nil {
            throw ResolutionError.invalidEntrySetDigestDeclaration
        }
        if checksums.keys.contains("asset_digest"),
           checksums["asset_digest"] as? String == nil {
            throw ResolutionError.invalidEntrySetDigestDeclaration
        }
        let declared = checksums["entry_set_digest"] as? String
        let legacy = checksums["asset_digest"] as? String

        if let declared, let legacy, declared != legacy {
            throw ResolutionError.conflictingEntrySetDigests
        }
        return declared ?? legacy
    }

    /// Compute E over the raw Runtime manifest and payload bytes.
    ///
    /// A checksum declaration is optional evidence and is never the source of
    /// this observation.
    public static func computeRuntimeEntrySetDigest(
        manifest: Data,
        payload: Data
    ) -> String {
        let entries = [
            ("kdna.json", manifest),
            ("payload.kdnab", payload),
        ]
        let combined = entries
            .sorted { KDNAContentDigest.utf8PathLess($0.0, $1.0) }
            .map { "\($0.0):\(KDNACrypto.sha256Hex($0.1))" }
            .joined(separator: "\n")
        return "sha256:\(KDNACrypto.sha256Hex(Data(combined.utf8)))"
    }
}
