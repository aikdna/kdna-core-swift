//  KDNACore — Cryptographic verification utilities
//
//  SHA-256 digest, Ed25519 signature verification, hex encoding/decoding.
//  Previously duplicated across native application service layers.

import Foundation
import CryptoKit
import CommonCrypto

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

    // MARK: - HKDF-SHA256 (RFC 5869)

    /// Derive keying material via HKDF-SHA256 extract-then-expand.
    public static func hkdfSha256(ikm: Data, salt: Data? = nil, info: Data = Data(), length: Int = 32) -> Data {
        let saltKey = salt ?? Data(count: 32)
        let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: saltKey))
        let t = HMAC<SHA256>.authenticationCode(for: info + Data([1]), using: SymmetricKey(data: Data(prk)))
        return Data(t).prefix(length)
    }

    // MARK: - AES-256-KW (RFC 3394)

    private static let kwIV: Data = Data([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])

    private static func aesECB(_ operation: CCOperation, key: Data, input: Data) -> Data {
        var output = Data(count: input.count)
        var numBytes: size_t = 0
        let outputCount = output.count
        let status = output.withUnsafeMutableBytes { outPtr in
            key.withUnsafeBytes { keyPtr in
                input.withUnsafeBytes { inPtr in
                    CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            keyPtr.baseAddress!, key.count, nil,
                            inPtr.baseAddress!, input.count,
                            outPtr.baseAddress!, outputCount, &numBytes)
                }
            }
        }
        guard status == kCCSuccess else {
            fatalError("AES-ECB operation failed with status \(status)")
        }
        return output.prefix(numBytes)
    }

    /// Wrap a 32-byte CEK with a 32-byte key-wrapping key (AES-256-KW).
    public static func aesKeyWrap(key: Data, plaintext: Data) throws -> Data {
        guard key.count == 32 else { throw KDNACryptoError.keyWrapInvalidKeySize }
        guard plaintext.count == 32 else { throw KDNACryptoError.keyWrapInvalidPlaintextSize }
        let n = plaintext.count / 8 // = 4 for 256-bit CEK
        var a = kwIV
        var r = [Data]()
        for i in 0..<n {
            r.append(plaintext.subdata(in: i*8..<(i+1)*8))
        }
        for j in 0...5 {
            for i in 0..<n {
                let input = a + r[i]
                let b = aesECB(CCOperation(kCCEncrypt), key: key, input: input)
                a = b.subdata(in: 0..<8)
                let t = UInt64(n * j + (i + 1))
                var aBytes = [UInt8](a)
                let tBytes = withUnsafeBytes(of: t.bigEndian) { Array($0) }
                for k in 0..<8 { aBytes[k] ^= tBytes[k] }
                a = Data(aBytes)
                r[i] = b.subdata(in: 8..<16)
            }
        }
        var result = a
        for i in 0..<n { result.append(r[i]) }
        return result // 40 bytes
    }

    /// Unwrap a 32-byte CEK from its 40-byte wrapped form (AES-256-KW).
    public static func aesKeyUnwrap(key: Data, ciphertext: Data) throws -> Data {
        guard key.count == 32 else { throw KDNACryptoError.keyWrapInvalidKeySize }
        guard ciphertext.count == 40 else { throw KDNACryptoError.keyWrapInvalidCiphertextSize }
        let n = (ciphertext.count / 8) - 1 // = 4
        var a = ciphertext.subdata(in: 0..<8)
        var r = [Data]()
        for i in 0..<n {
            r.append(ciphertext.subdata(in: (i+1)*8..<(i+2)*8))
        }
        for j in (0...5).reversed() {
            for i in (0..<n).reversed() {
                let t = UInt64(n * j + (i + 1))
                var aBytes = [UInt8](a)
                let tBytes = withUnsafeBytes(of: t.bigEndian) { Array($0) }
                for k in 0..<8 { aBytes[k] ^= tBytes[k] }
                a = Data(aBytes)
                let input = a + r[i]
                let b = aesECB(CCOperation(kCCDecrypt), key: key, input: input)
                a = b.subdata(in: 0..<8)
                r[i] = b.subdata(in: 8..<16)
            }
        }
        guard a == kwIV else { throw KDNACryptoError.keyWrapIntegrityCheckFailed }
        var result = Data()
        for i in 0..<n { result.append(r[i]) }
        return result // 32 bytes
    }
}

// MARK: - Errors

public enum KDNACryptoError: Error, LocalizedError {
    case sha256Mismatch(expected: String, actual: String)
    case missingPublicKey
    case invalidPublicKey
    case invalidSignature
    case signatureVerificationFailed
    case keyWrapInvalidKeySize
    case keyWrapInvalidPlaintextSize
    case keyWrapInvalidCiphertextSize
    case keyWrapIntegrityCheckFailed

    public var errorDescription: String? {
        switch self {
        case .sha256Mismatch(let e, let a):
            return "SHA-256 mismatch: expected \(e.prefix(16))…, got \(a.prefix(16))…"
        case .missingPublicKey: return "Missing Ed25519 public key"
        case .invalidPublicKey: return "Invalid Ed25519 public key format"
        case .invalidSignature: return "Invalid Ed25519 signature format"
        case .signatureVerificationFailed: return "Ed25519 signature verification failed"
        case .keyWrapInvalidKeySize: return "AES-256-KW requires a 32-byte key"
        case .keyWrapInvalidPlaintextSize: return "AES-256-KW requires 32-byte plaintext"
        case .keyWrapInvalidCiphertextSize: return "AES-256-KW ciphertext must be 40 bytes"
        case .keyWrapIntegrityCheckFailed: return "AES-256-KW unwrap: integrity check failed"
        }
    }
}
