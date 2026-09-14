import Foundation

/// Resolves the digest of the integrity-covered entry set declared by
/// `checksums.json`.
///
/// `entry_set_digest` is the sole current field name. No deprecated digest
/// declaration aliases are accepted at the Runtime boundary.
public enum KDNAChecksumDigests {
    public static let runtimeEntrySetProfile = "kdna.digest-basis.runtime-entry-set"
    public static let runtimeEntrySetProfileVersion = "0.1.0"
    public static let runtimeCoveredEntries = ["kdna.json", "payload.kdnab"]

    public enum ResolutionError: Error {
        case invalidEntrySetDigestDeclaration
        case invalidDigestProfile
        case invalidDigestProfileVersion
        case invalidCoveredEntries
    }

    public static func validateMetadata(in checksums: [String: Any]) throws {
        if checksums.keys.contains("digest_profile"),
           checksums["digest_profile"] as? String != runtimeEntrySetProfile {
            throw ResolutionError.invalidDigestProfile
        }
        if checksums.keys.contains("digest_profile_version"),
           checksums["digest_profile_version"] as? String != runtimeEntrySetProfileVersion {
            throw ResolutionError.invalidDigestProfileVersion
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
        return checksums["entry_set_digest"] as? String
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
