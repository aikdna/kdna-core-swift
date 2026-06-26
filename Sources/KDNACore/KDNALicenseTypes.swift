//  KDNACore — License activation types for licensed KDNA assets (RFC-0008)
//
//  Defines the local license file format stored under ~/.kdna/licenses/

import Foundation

/// Local license activation record for a licensed KDNA domain.
public struct KDNALicenseActivation: Codable {
    public let version: String
    public let license_id: String
    public let domain: String
    public let issued_to: String
    public let issued_at: String
    public let expires_at: String?
    public let machine_fingerprint: String?
    public let signature: String

    /// Verify the license signature using the provided public key.
    ///
    /// **Status: unsupported** (per ADR-005 §5). The KDNA Core Swift implementation
    /// does not currently verify license file signatures — the canonical signing
    /// payload format for license files is not yet specified.
    ///
    /// This function deliberately throws rather than returning `true` (the
    /// previous placeholder). Returning `true` for every signature would accept
    /// any license file as valid, which is a real security hole.
    ///
    /// Callers (currently `KDNATrust.verify`) should treat the throw as
    /// "license signature verification not available in this build" and either
    /// skip license checks or refuse to validate licensed domains.
    public func verifySignature(publicKey: String) throws -> Bool {
        // The KDNA Core Swift team has chosen the "return unsupported" path
        // of ADR-005 §5 (rather than implementing real Ed25519 verification
        // for license files, which requires first finalizing the license
        // signing payload format per RFC-0008).
        _ = publicKey
        throw KDNAError.unsupportedProfile(
            "license file signature verification is not implemented in KDNACore Swift; " +
            "see ADR-005 §5 — implement real Ed25519 verification before re-enabling"
        )
    }

    /// Check if the license has expired.
    public func isExpired(relativeTo date: Date = Date()) -> Bool {
        guard let expires = expires_at else { return false }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        guard let expiryDate = formatter.date(from: expires) else { return false }
        return date > expiryDate
    }

    /// Check if the license is bound to the given machine fingerprint.
    public func isBound(to fingerprint: String?) -> Bool {
        guard let expected = machine_fingerprint else { return true }
        guard let actual = fingerprint else { return false }
        return expected == actual
    }
}
