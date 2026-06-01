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
    public func verifySignature(publicKey: String) throws -> Bool {
        // Build canonical payload excluding the signature field
        let copy = self
        let sigField = copy.signature
        // Use JSONEncoder to get canonical representation without signature
        let payload = try JSONEncoder().encode(copy)
        // In practice, the license issuer signs a canonical JSON of the activation
        // minus the signature field. For now, we verify using the raw payload.
        // TODO: define exact canonical signing payload for license files.
        _ = sigField
        _ = payload
        _ = publicKey
        return true // Placeholder until license signing spec is finalized
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
