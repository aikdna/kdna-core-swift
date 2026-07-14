import Foundation

/// Resolves the digest of the integrity-covered entry set declared by
/// `checksums.json`.
///
/// `entry_set_digest` is the unambiguous field name. `asset_digest` remains a
/// deprecated compatibility alias for KDNA 1.0 containers, Runtime Capsule
/// 1.0, and external grant v1. When both fields are present they must agree.
enum KDNAChecksumDigests {
    static let runtimeEntrySetProfile = "kdna-runtime-entry-set-v1"
    static let runtimeCoveredEntries = ["kdna.json", "payload.kdnab"]

    enum ResolutionError: Error {
        case conflictingEntrySetDigests
        case invalidEntrySetDigestDeclaration
        case invalidDigestProfile
        case invalidCoveredEntries
    }

    static func validateMetadata(in checksums: [String: Any]) throws {
        if checksums.keys.contains("digest_profile"),
           checksums["digest_profile"] as? String != runtimeEntrySetProfile {
            throw ResolutionError.invalidDigestProfile
        }
        if checksums.keys.contains("covered_entries"),
           checksums["covered_entries"] as? [String] != runtimeCoveredEntries {
            throw ResolutionError.invalidCoveredEntries
        }
    }

    static func entrySetDigest(in checksums: [String: Any]) throws -> String? {
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
}
