import Foundation
import CryptoKit
import Argon2Swift

// MARK: - RFC-0009 Password-Protected Asset Profile

public let PASSWORD_PROTECTED_PROFILE = "kdna-password-protected-v1"
public let PASSWORD_KDF_NAME = "Argon2id"

public struct KDNAPasswordKDFParams: Codable {
    public let name: String
    public let salt: String
    public let memory_kib: Int
    public let iterations: Int
    public let parallelism: Int

    public init(name: String = PASSWORD_KDF_NAME, salt: String, memory_kib: Int = 65536, iterations: Int = 3, parallelism: Int = 4) {
        self.name = name
        self.salt = salt
        self.memory_kib = memory_kib
        self.iterations = iterations
        self.parallelism = parallelism
    }
}

public struct KDNAKeySlot: Codable {
    public let slot: String
    public let wrap: String
    public let wrapped_key: String
}

public struct KDNAProtectedEnvelope: Codable {
    public let profile: String
    public let alg: String
    public let kdf: String
    public let key_wrapping: String
    public let password_kdf: KDNAPasswordKDFParams
    public let key_slots: [KDNAKeySlot]
    public let iv: String
    public let tag: String
    public let ciphertext: String
}

// MARK: - Recovery Code

public func generateRecoveryCode() -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        fatalError("Failed to generate secure random bytes for recovery code")
    }
    let hex = bytes.map { String(format: "%02X", $0) }.joined()
    let groups = stride(from: 0, to: hex.count, by: 4).map {
        let start = hex.index(hex.startIndex, offsetBy: $0)
        let end = hex.index(start, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
        return String(hex[start..<end])
    }
    return "kdna-recover-\(groups.joined(separator: "-"))"
}

public func decodeRecoveryCode(_ code: String) throws -> Data {
    guard code.hasPrefix("kdna-recover-") else {
        throw KDNAError.invalidRecoveryCode("recovery code must start with 'kdna-recover-'")
    }
    let hex = code.dropFirst("kdna-recover-".count).replacingOccurrences(of: "-", with: "")
    guard hex.count == 64, let data = hexToData(hex) else {
        throw KDNAError.invalidRecoveryCode("recovery code format is invalid")
    }
    return data
}

private func hexToData(_ hex: String) -> Data? {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
        data.append(byte)
        index = nextIndex
    }
    return data
}

// MARK: - Argon2id Key Derivation

public func derivePasswordKey(password: String, params: KDNAPasswordKDFParams) throws -> Data {
    guard params.name == PASSWORD_KDF_NAME else {
        throw KDNAError.unsupportedKDF("unsupported password KDF: \(params.name)")
    }
    let salt = Salt(bytes: Data(base64Encoded: params.salt) ?? Data())
    let result = try Argon2Swift.hashPasswordBytes(
        password: Data(password.utf8),
        salt: salt,
        iterations: params.iterations,
        memory: params.memory_kib,
        parallelism: params.parallelism,
        length: 32,
        type: .id,
        version: .V13
    )
    return result.hashData()
}

// MARK: - Encryption / Decryption

public func encryptProtectedEntry(
    plaintext: Data,
    entryName: String,
    manifest: KDNAManifest,
    password: String,
    includeRecovery: Bool = true,
    recoveryCode: String? = nil
) throws -> KDNAProtectedEnvelope {
    // Generate CEK
    let cek = SymmetricKey(size: .bits256)
    let cekData = cek.withUnsafeBytes { Data($0) }

    // Password slot
    let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
    let passwordKdf = KDNAPasswordKDFParams(
        salt: salt.base64EncodedString(),
        memory_kib: 65536,
        iterations: 3,
        parallelism: 4
    )
    let passwordKey = try derivePasswordKey(password: password, params: passwordKdf)
    let passwordWrappedKey = try KDNACrypto.aesKeyWrap(key: passwordKey, plaintext: cekData)

    var keySlots: [KDNAKeySlot] = [
        KDNAKeySlot(slot: "password", wrap: "AES-256-KW", wrapped_key: passwordWrappedKey.base64EncodedString())
    ]

    // Recovery slot
    if includeRecovery {
        let recoveryKey: Data
        if let code = recoveryCode {
            recoveryKey = try decodeRecoveryCode(code)
        } else {
            var recoveryKeyBytes = [UInt8](repeating: 0, count: 32)
            let status = SecRandomCopyBytes(kSecRandomDefault, recoveryKeyBytes.count, &recoveryKeyBytes)
            guard status == errSecSuccess else { fatalError("Failed to generate recovery key") }
            recoveryKey = Data(recoveryKeyBytes)
        }
        let recoveryWrappedKey = try KDNACrypto.aesKeyWrap(key: recoveryKey, plaintext: cekData)
        keySlots.append(KDNAKeySlot(slot: "recovery", wrap: "AES-256-KW", wrapped_key: recoveryWrappedKey.base64EncodedString()))
    }

    // Encrypt content
    let iv = AES.GCM.Nonce()
    let aad = protectedEntryAad(entryName: entryName, manifest: manifest)
    let sealedBox = try AES.GCM.seal(plaintext, using: cek, nonce: iv, authenticating: aad)

    return KDNAProtectedEnvelope(
        profile: PASSWORD_PROTECTED_PROFILE,
        alg: "AES-256-GCM",
        kdf: PASSWORD_KDF_NAME,
        key_wrapping: "AES-256-KW",
        password_kdf: passwordKdf,
        key_slots: keySlots,
        iv: Data(iv).base64EncodedString(),
        tag: sealedBox.tag.base64EncodedString(),
        ciphertext: sealedBox.ciphertext.base64EncodedString()
    )
}

public func decryptProtectedEntry(
    envelope: KDNAProtectedEnvelope,
    entryName: String,
    manifest: KDNAManifest,
    password: String? = nil,
    recoveryCode: String? = nil
) throws -> Data {
    guard envelope.profile == PASSWORD_PROTECTED_PROFILE else {
        throw KDNAError.unsupportedProfile("unsupported profile: \(envelope.profile)")
    }
    guard envelope.alg == "AES-256-GCM" else {
        throw KDNAError.unsupportedAlgorithm("unsupported algorithm: \(envelope.alg)")
    }
    guard envelope.kdf == PASSWORD_KDF_NAME else {
        throw KDNAError.unsupportedKDF("unsupported KDF: \(envelope.kdf)")
    }
    guard envelope.key_wrapping == "AES-256-KW" else {
        throw KDNAError.unsupportedKeyWrapping("unsupported key wrapping: \(envelope.key_wrapping)")
    }
    guard password != nil || recoveryCode != nil else {
        throw KDNAError.missingCredential("password or recoveryCode is required")
    }

    let cekData: Data
    if let password = password {
        let passwordKey = try derivePasswordKey(password: password, params: envelope.password_kdf)
        guard let passwordSlot = envelope.key_slots.first(where: { $0.slot == "password" }) else {
            throw KDNAError.missingKeySlot("password slot missing from envelope")
        }
        cekData = try KDNACrypto.aesKeyUnwrap(key: passwordKey, ciphertext: Data(base64Encoded: passwordSlot.wrapped_key) ?? Data())
    } else if let recoveryCode = recoveryCode {
        let recoveryKey = try decodeRecoveryCode(recoveryCode)
        guard let recoverySlot = envelope.key_slots.first(where: { $0.slot == "recovery" }) else {
            throw KDNAError.missingKeySlot("recovery slot missing from envelope")
        }
        cekData = try KDNACrypto.aesKeyUnwrap(key: recoveryKey, ciphertext: Data(base64Encoded: recoverySlot.wrapped_key) ?? Data())
    } else {
        throw KDNAError.missingCredential("password or recoveryCode is required")
    }

    let cek = SymmetricKey(data: cekData)
    guard let ivData = Data(base64Encoded: envelope.iv),
          let ciphertext = Data(base64Encoded: envelope.ciphertext),
          let tag = Data(base64Encoded: envelope.tag) else {
        throw KDNAError.invalidEnvelope("invalid base64 in envelope")
    }
    let nonce = try AES.GCM.Nonce(data: ivData)
    let aad = protectedEntryAad(entryName: entryName, manifest: manifest)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    return try AES.GCM.open(sealedBox, using: cek, authenticating: aad)
}

// MARK: - Hook Factories

public func createPasswordDecryptEntry(password: String) -> KDNADecryptEntry {
    return { asset, manifest, entryName, ciphertext in
        let envelope = try KDNACBOR.decode(KDNAProtectedEnvelope.self, from: ciphertext)
        return try decryptProtectedEntry(
            envelope: envelope,
            entryName: entryName,
            manifest: manifest,
            password: password
        )
    }
}

public func createRecoveryDecryptEntry(recoveryCode: String) -> KDNADecryptEntry {
    return { asset, manifest, entryName, ciphertext in
        let envelope = try KDNACBOR.decode(KDNAProtectedEnvelope.self, from: ciphertext)
        return try decryptProtectedEntry(
            envelope: envelope,
            entryName: entryName,
            manifest: manifest,
            recoveryCode: recoveryCode
        )
    }
}

// MARK: - AAD

private func protectedEntryAad(entryName: String, manifest: KDNAManifest) -> Data {
    let lines = [
        PASSWORD_PROTECTED_PROFILE,
        manifest.name,
        manifest.version,
        entryName
    ]
    return lines.joined(separator: "\n").data(using: String.Encoding.utf8)!
}

// MARK: - Error Types

public enum KDNAError: Error {
    case invalidRecoveryCode(String)
    case unsupportedKDF(String)
    case unsupportedProfile(String)
    case unsupportedAlgorithm(String)
    case unsupportedKeyWrapping(String)
    case missingCredential(String)
    case missingKeySlot(String)
    case encryptionFailed(String)
    case invalidEnvelope(String)
    case invalidKeySize(String)
    case wrapIntegrityFailed(String)
    case invalidBlockSize(String)
}
