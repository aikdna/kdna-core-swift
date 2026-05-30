//  KDNACore — Cryptographic verification utilities
//
//  SHA-256 digest, Ed25519 signature verification, hex encoding/decoding.
//  Previously duplicated in KDNaStudio and KDNAChat app Services/.

import Foundation
import CryptoKit

public class KDNACrypto {

    // MARK: - SHA-256

    /// Compute SHA-256 hash of data and return as lowercase hex string.
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
    }

    /// Verify SHA-256 hash of data against expected value.
    /// Accepts both raw hex and "sha256:<hex>" format.
    public static func verifySHA256(_ data: Data, expected: String) throws {
        let actual = sha256Hex(data)
        let normalized = expected
            .lowercased()
            .replacingOccurrences(of: "sha256:", with: "")
        guard actual.lowercased() == normalized else {
            throw KDNACryptoError.sha256Mismatch(expected: expected, actual: actual)
        }
    }

    // MARK: - Ed25519

    /// Verify Ed25519 signature using a raw public key (32 bytes).
    public static func verifyEd25519(_ data: Data, signatureHex: String, publicKeyHex: String) throws {
        guard let pkData = hexDecode(publicKeyHex) else {
            throw KDNACryptoError.invalidPublicKey
        }
        guard let sigData = hexDecode(signatureHex) else {
            throw KDNACryptoError.invalidSignature
        }
        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pkData)
        } catch {
            throw KDNACryptoError.invalidPublicKey
        }
        guard publicKey.isValidSignature(sigData, for: data) else {
            throw KDNACryptoError.signatureVerificationFailed
        }
    }

    /// Verify Ed25519 signature using a PEM-encoded public key.
    public static func verifyEd25519PEM(_ data: Data, signatureHex: String, publicKeyPEM: String) throws {
        let rawKey = try rawEd25519PublicKey(fromPEM: publicKeyPEM)
        try verifyEd25519(data, signatureHex: signatureHex, publicKeyHex: rawKey)
    }

    /// Extract raw 32-byte Ed25519 public key from PEM or DER.
    public static func rawEd25519PublicKey(fromPEM pem: String) throws -> String {
        // Remove PEM headers/footers and whitespace
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)
        guard let der = Data(base64Encoded: base64) else {
            throw KDNACryptoError.invalidPublicKey
        }
        // Ed25519 SPKI DER: last 32 bytes are the raw key
        guard der.count >= 32 else { throw KDNACryptoError.invalidPublicKey }
        return hexEncode(der.suffix(32))
    }

    // MARK: - Hex

    /// Convert hex string to Data.
    public static func hexDecode(_ hex: String) -> Data? {
        let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        var data = Data()
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2, limitedBy: clean.endIndex) ?? clean.endIndex
            let byteStr = clean[index..<next]
            guard byteStr.count == 2, let byte = UInt8(byteStr, radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    /// Convert Data to lowercase hex string.
    public static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Errors

public enum KDNACryptoError: Error, LocalizedError {
    case sha256Mismatch(expected: String, actual: String)
    case missingPublicKey
    case invalidPublicKey
    case invalidSignature
    case signatureVerificationFailed

    public var errorDescription: String? {
        switch self {
        case .sha256Mismatch(let e, let a):
            return "SHA-256 mismatch: expected \(e.prefix(16))…, got \(a.prefix(16))…"
        case .missingPublicKey: return "Missing Ed25519 public key"
        case .invalidPublicKey: return "Invalid Ed25519 public key format"
        case .invalidSignature: return "Invalid Ed25519 signature format"
        case .signatureVerificationFailed: return "Ed25519 signature verification failed"
        }
    }
}
