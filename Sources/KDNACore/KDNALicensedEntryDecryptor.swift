//  KDNACore — Licensed entry decryptor for RFC-0008 encrypted KDNA assets
//
//  Decrypts protected entries inside a .kdna container using the sole current
//  licensed-entry profile (HKDF-SHA256 + AES-256-KW + AES-256-GCM).

import Foundation
import CryptoKit

public let KDNA_LICENSED_ENTRY_PROFILE = "kdna.encryption.licensed-entry"
public let KDNA_ENCRYPTION_PROFILE_VERSION = "0.1.0"

/// Encrypted entry envelope stored as canonical CBOR inside the container.
public struct KDNALicensedEntryEnvelope: Codable, Equatable, Sendable {
    public let profile: String
    public let profile_version: String
    public let alg: String
    public let kdf: String
    public let key_wrapping: String
    public let wrapped_key: String
    public let iv: String
    public let tag: String
    public let ciphertext: String
}

/// Decryptor for licensed KDNA asset entries.
public class KDNALicensedEntryDecryptor {

    public let licenseKey: String

    public init(licenseKey: String) {
        self.licenseKey = licenseKey
    }

    /// Decrypt a single licensed entry.
    public func decrypt(entryName: String, envelopeData: Data, manifest: KDNAManifest) throws -> Data {
        let envelope = try KDNACBOR.decode(KDNALicensedEntryEnvelope.self, from: envelopeData)

        guard envelope.profile == KDNA_LICENSED_ENTRY_PROFILE else {
            throw KDNALicensedEntryError.unsupportedProfile(envelope.profile)
        }
        guard envelope.profile_version == KDNA_ENCRYPTION_PROFILE_VERSION else {
            throw KDNALicensedEntryError.unsupportedProfileVersion(envelope.profile_version)
        }
        return try decryptCurrent(entryName: entryName, envelope: envelope, manifest: manifest)
    }

    // MARK: - Current licensed entry contract

    private func decryptCurrent(entryName: String, envelope: KDNALicensedEntryEnvelope, manifest: KDNAManifest) throws -> Data {
        guard envelope.alg == "AES-256-GCM" else {
            throw KDNALicensedEntryError.unsupportedAlgorithm(envelope.alg)
        }
        guard envelope.kdf == "HKDF-SHA256" else {
            throw KDNALicensedEntryError.unsupportedKDF(envelope.kdf)
        }
        guard envelope.key_wrapping == "AES-256-KW" else {
            throw KDNALicensedEntryError.unsupportedKeyWrapping(envelope.key_wrapping)
        }

        let wrappingKey = deriveWrappingKey(licenseKey: licenseKey)
        let wrappedKey = try base64Decode(envelope.wrapped_key)
        let cek = try KDNACrypto.aesKeyUnwrap(key: wrappingKey, ciphertext: wrappedKey)

        let iv = try base64Decode(envelope.iv)
        let tag = try base64Decode(envelope.tag)
        let ciphertext = try base64Decode(envelope.ciphertext)

        let aad = encryptedEntryAad(entryName: entryName, manifest: manifest)

        let nonce = try AES.GCM.Nonce(data: iv)
        let symmetricKey = SymmetricKey(data: cek)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        return plaintext
    }

    // MARK: - Helpers

    private func deriveWrappingKey(licenseKey: String) -> Data {
        let info = Data("kdna.encryption.licensed-entry-kwk".utf8)
        return KDNACrypto.hkdfSha256(ikm: Data(licenseKey.utf8), info: info, length: 32)
    }

    private func encryptedEntryAad(entryName: String, manifest: KDNAManifest) -> Data {
        let lines = [
            KDNA_LICENSED_ENTRY_PROFILE,
            KDNA_ENCRYPTION_PROFILE_VERSION,
            manifest.asset_id,
            manifest.version,
            entryName,
        ]
        return Data(lines.joined(separator: "\n").utf8)
    }

    private func base64Decode(_ value: String) throws -> Data {
        guard let data = Data(base64Encoded: value) else {
            throw KDNALicensedEntryError.invalidBase64
        }
        return data
    }
}

/// Factory function matching JS `createLicensedDecryptEntry`.
public func createLicensedDecryptEntry(licenseKey: String, machineFingerprint: String? = nil) -> KDNADecryptEntry {
    let decryptor = KDNALicensedEntryDecryptor(licenseKey: licenseKey)
    return { asset, manifest, entryName, ciphertext in
        try decryptor.decrypt(entryName: entryName, envelopeData: ciphertext, manifest: manifest)
    }
}

public typealias KDNADecryptEntry = (KDNAAsset, KDNAManifest, String, Data) throws -> Data

public enum KDNALicensedEntryError: Error, LocalizedError {
    case unsupportedProfile(String)
    case unsupportedProfileVersion(String)
    case unsupportedAlgorithm(String)
    case unsupportedKDF(String)
    case unsupportedKeyWrapping(String)
    case invalidBase64

    public var errorDescription: String? {
        switch self {
        case .unsupportedProfile(let p): return "Unsupported encrypted entry profile: \(p)"
        case .unsupportedProfileVersion(let version): return "Unsupported encrypted entry profile_version: \(version)"
        case .unsupportedAlgorithm(let a): return "Unsupported encrypted entry algorithm: \(a)"
        case .unsupportedKDF(let k): return "Unsupported encrypted entry KDF: \(k)"
        case .unsupportedKeyWrapping(let w): return "Unsupported encrypted entry key wrapping: \(w)"
        case .invalidBase64: return "Invalid base64 in encrypted entry envelope"
        }
    }
}
