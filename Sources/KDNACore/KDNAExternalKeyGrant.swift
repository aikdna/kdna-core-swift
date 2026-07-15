import Foundation
import CryptoKit

public let KDNA_EXTERNAL_ENVELOPE_PROFILE = "kdna.envelope.external-grant"
public let KDNA_EXTERNAL_GRANT_PROFILE = "kdna.grant.external-key"
public let KDNA_EXTERNAL_GRANT_CONTRACT_VERSION = "0.1.0"
public let KDNA_DEVICE_GRANT_KEY_CONTEXT = "kdna.key-context.device-grant"

public enum KDNAExternalGrantError: Error, LocalizedError, Equatable {
    case failure(code: String, message: String)

    public var code: String {
        switch self { case .failure(let code, _): return code }
    }

    public var errorDescription: String? {
        switch self { case .failure(_, let message): return message }
    }
}

public struct KDNAExternalEnvelope: Codable, Equatable {
    public let profile: String
    public let contract_version: String
    public let alg: String
    public let cek_derivation: String
    public let key_ref: String
    public let issuer_key_id: String
    public let entry_path: String
    public let plaintext_digest: String
    public let iv: String
    public let tag: String
    public let ciphertext: String
}

public struct KDNAExternalGrantAsset: Codable, Equatable {
    public let asset_id: String
    public let asset_uid: String
    public let version: String
    public let digest: String
    public let entry_path: String
    public let ciphertext_digest: String
    public let key_ref: String
    public let issuer_key_id: String
}

public struct KDNAExternalGrantWrap: Codable, Equatable {
    public let alg: String
    public let ephemeral_public_key: String
    public let salt: String
    public let wrapped_cek: String
}

public struct KDNAExternalKeyGrant: Codable, Equatable {
    public let profile: String
    public let contract_version: String
    public let grant_id: String
    public let issuer: String
    public let signing_key_id: String
    public let entitlement_id: String
    public let account_id: String
    public let device_id: String
    public let device_public_key: String
    public let device_signing_public_key: String
    public let asset: KDNAExternalGrantAsset
    public let issued_at: String
    public let refresh_after: String
    public let offline_grace_until: String
    public let expires_at: String
    public let status: String
    public let status_version: Int
    public let wrap: KDNAExternalGrantWrap
    public let signature: String
}

/// A verified, in-memory authorization. Its initializer is private so a plain
/// `status: active` value cannot manufacture an account entitlement.
public final class KDNAExternalGrantAuthorization: Equatable {
    public let grant: KDNAExternalKeyGrant
    public let entitlementStatus: String
    private var cek: [UInt8]

    private init(grant: KDNAExternalKeyGrant, entitlementStatus: String, cek: Data) {
        self.grant = grant
        self.entitlementStatus = entitlementStatus
        self.cek = Array(cek)
    }

    deinit {
        dispose()
    }

    public func dispose() {
        for index in cek.indices { cek[index] = 0 }
        cek.removeAll(keepingCapacity: false)
    }

    public static func == (lhs: KDNAExternalGrantAuthorization, rhs: KDNAExternalGrantAuthorization) -> Bool {
        lhs === rhs
    }

    public static func authorize(
        grantData: Data,
        envelopeData: Data,
        manifest: [String: Any],
        expectedAssetDigest: String,
        issuerPublicKeys: [String: String],
        deviceAgreementPrivateKey: String,
        expectedAccountID: String,
        expectedDeviceID: String,
        expectedDevicePublicKey: String,
        expectedDeviceSigningPublicKey: String,
        minimumStatusVersion: Int? = nil,
        minimumVerifiedTime: Date? = nil,
        now: Date = Date(),
        networkAvailable: Bool = false,
        allowOffline: Bool = true
    ) throws -> KDNAExternalGrantAuthorization {
        let grantObject = try strictJSONObject(grantData, keys: grantKeys, code: "KDNA_GRANT_FORMAT_INVALID")
        guard let assetObject = grantObject["asset"] as? [String: Any],
              Set(assetObject.keys) == grantAssetKeys,
              let wrapObject = grantObject["wrap"] as? [String: Any],
              Set(wrapObject.keys) == grantWrapKeys else {
            throw failure("KDNA_GRANT_FORMAT_INVALID", "external key grant has unknown or missing fields")
        }
        let grant: KDNAExternalKeyGrant
        do { grant = try JSONDecoder().decode(KDNAExternalKeyGrant.self, from: grantData) }
        catch { throw failure("KDNA_GRANT_FORMAT_INVALID", "external key grant JSON is invalid") }
        try validateGrantShape(grant)

        guard let pinned = issuerPublicKeys[grant.signing_key_id] else {
            throw failure("KDNA_GRANT_ISSUER_UNKNOWN", "grant signing key is not pinned")
        }
        let publicKeyData = try prefixed(pinned, prefix: "ed25519", count: 32, label: "issuer public key")
        let signatureData = try prefixed(grant.signature, prefix: "ed25519", count: 64, label: "grant signature")
        let verifier: Curve25519.Signing.PublicKey
        do { verifier = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) }
        catch { throw failure("KDNA_GRANT_ISSUER_UNKNOWN", "grant signing key is invalid") }
        let signingData = try canonicalSigningData(grantObject)
        guard verifier.isValidSignature(signatureData, for: signingData) else {
            throw failure("KDNA_GRANT_SIGNATURE_INVALID", "external key grant signature is invalid")
        }
        if let minimumStatusVersion, grant.status_version < minimumStatusVersion {
            throw failure("KDNA_GRANT_ROLLBACK_DETECTED", "external key grant status version rolled back")
        }
        if let minimumVerifiedTime, now.addingTimeInterval(5 * 60) < minimumVerifiedTime {
            throw failure("KDNA_AUTH_CLOCK_ROLLBACK", "system clock moved behind the last verified grant time")
        }

        let state = try grantState(grant, now: now, networkAvailable: networkAvailable, allowOffline: allowOffline)
        let envelope = try decodeEnvelope(envelopeData)
        try equal(grant.account_id, expectedAccountID, code: "KDNA_GRANT_ACCOUNT_MISMATCH", label: "grant account")
        try equal(grant.device_id, expectedDeviceID, code: "KDNA_GRANT_DEVICE_MISMATCH", label: "grant device")
        try equal(grant.device_public_key, expectedDevicePublicKey, code: "KDNA_GRANT_DEVICE_MISMATCH", label: "device agreement key")
        try equal(grant.device_signing_public_key, expectedDeviceSigningPublicKey, code: "KDNA_GRANT_DEVICE_MISMATCH", label: "device signing key")
        try equal(grant.asset.asset_id, manifest["asset_id"] as? String, code: "KDNA_GRANT_ASSET_MISMATCH", label: "asset ID")
        try equal(grant.asset.asset_uid, manifest["asset_uid"] as? String, code: "KDNA_GRANT_ASSET_MISMATCH", label: "asset UID")
        try equal(grant.asset.version, manifest["version"] as? String, code: "KDNA_GRANT_ASSET_MISMATCH", label: "asset version")
        try equal(grant.asset.digest, expectedAssetDigest, code: "KDNA_GRANT_DIGEST_MISMATCH", label: "asset digest")
        try equal(grant.asset.entry_path, envelope.entry_path, code: "KDNA_GRANT_ASSET_MISMATCH", label: "entry path")
        try equal(grant.asset.key_ref, envelope.key_ref, code: "KDNA_GRANT_ASSET_MISMATCH", label: "key reference")
        try equal(grant.asset.issuer_key_id, envelope.issuer_key_id, code: "KDNA_GRANT_ASSET_MISMATCH", label: "issuer asset key")
        let ciphertext = try base64url(envelope.ciphertext, count: nil, label: "envelope ciphertext")
        try equal(grant.asset.ciphertext_digest, digest(ciphertext), code: "KDNA_GRANT_DIGEST_MISMATCH", label: "ciphertext digest")

        var privateRaw = try prefixed(deviceAgreementPrivateKey, prefix: "x25519", count: 32, label: "device private key")
        defer { privateRaw.resetBytes(in: privateRaw.startIndex..<privateRaw.endIndex) }
        let ephemeralRaw = try prefixed(grant.wrap.ephemeral_public_key, prefix: "x25519", count: 32, label: "ephemeral public key")
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let ephemeralKey: Curve25519.KeyAgreement.PublicKey
        do {
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateRaw)
            ephemeralKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralRaw)
        } catch {
            throw failure("KDNA_GRANT_DEVICE_KEY_INVALID", "device agreement key is invalid")
        }
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        let salt = try base64url(grant.wrap.salt, count: 16, label: "grant wrap salt")
        let kekKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("\(KDNA_DEVICE_GRANT_KEY_CONTEXT)\n\(KDNA_EXTERNAL_GRANT_CONTRACT_VERSION)\n\(grant.grant_id)".utf8),
            outputByteCount: 32
        )
        var kek = kekKey.withUnsafeBytes { Data($0) }
        defer { kek.resetBytes(in: kek.startIndex..<kek.endIndex) }
        let wrapped = try base64url(grant.wrap.wrapped_cek, count: 40, label: "wrapped CEK")
        var cek: Data
        do { cek = try KDNACrypto.aesKeyUnwrap(key: kek, ciphertext: wrapped) }
        catch { throw failure("KDNA_GRANT_DEVICE_MISMATCH", "device could not unwrap the external key grant") }
        defer { cek.resetBytes(in: cek.startIndex..<cek.endIndex) }
        return KDNAExternalGrantAuthorization(grant: grant, entitlementStatus: state, cek: cek)
    }

    public func decrypt(entryName: String, envelopeData: Data, manifest: [String: Any]) throws -> Data {
        let envelope = try Self.decodeEnvelope(envelopeData)
        try Self.equal(entryName, grant.asset.entry_path, code: "KDNA_GRANT_ASSET_MISMATCH", label: "entry path")
        let encrypted = try Self.base64url(envelope.ciphertext, count: nil, label: "envelope ciphertext")
        try Self.equal(Self.digest(encrypted), grant.asset.ciphertext_digest, code: "KDNA_GRANT_DIGEST_MISMATCH", label: "ciphertext digest")
        let aad = try Self.aad(manifest: manifest, envelope: envelope, entryName: entryName)
        let nonceData = try Self.base64url(envelope.iv, count: 12, label: "envelope IV")
        let tag = try Self.base64url(envelope.tag, count: 16, label: "envelope tag")
        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted, tag: tag)
            let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: Data(cek)), authenticating: aad)
            try Self.equal(Self.digest(plaintext), envelope.plaintext_digest, code: "KDNA_GRANT_DIGEST_MISMATCH", label: "plaintext digest")
            return plaintext
        } catch let error as KDNAExternalGrantError {
            throw error
        } catch {
            throw Self.failure("KDNA_GRANT_TAMPERED", "external envelope authentication failed")
        }
    }

    private static let envelopeKeys: Set<String> = ["profile", "contract_version", "alg", "cek_derivation", "key_ref", "issuer_key_id", "entry_path", "plaintext_digest", "iv", "tag", "ciphertext"]
    private static let grantKeys: Set<String> = ["profile", "contract_version", "grant_id", "issuer", "signing_key_id", "entitlement_id", "account_id", "device_id", "device_public_key", "device_signing_public_key", "asset", "issued_at", "refresh_after", "offline_grace_until", "expires_at", "status", "status_version", "wrap", "signature"]
    private static let grantAssetKeys: Set<String> = ["asset_id", "asset_uid", "version", "digest", "entry_path", "ciphertext_digest", "key_ref", "issuer_key_id"]
    private static let grantWrapKeys: Set<String> = ["alg", "ephemeral_public_key", "salt", "wrapped_cek"]

    private static func decodeEnvelope(_ data: Data) throws -> KDNAExternalEnvelope {
        let object: [String: Any]
        do { object = try KDNACBOR.decodeObject(data) }
        catch { throw failure("KDNA_ENVELOPE_FORMAT_INVALID", "external envelope CBOR is invalid") }
        guard Set(object.keys) == envelopeKeys else {
            throw failure("KDNA_ENVELOPE_FORMAT_INVALID", "external envelope has unknown or missing fields")
        }
        let json = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        let envelope: KDNAExternalEnvelope
        do { envelope = try JSONDecoder().decode(KDNAExternalEnvelope.self, from: json) }
        catch { throw failure("KDNA_ENVELOPE_FORMAT_INVALID", "external envelope is invalid") }
        guard envelope.profile == KDNA_EXTERNAL_ENVELOPE_PROFILE,
              envelope.contract_version == KDNA_EXTERNAL_GRANT_CONTRACT_VERSION,
              envelope.alg == "A256GCM", envelope.cek_derivation == "HKDF-SHA256" else {
            throw failure("KDNA_ENVELOPE_FORMAT_INVALID", "external envelope profile is unsupported")
        }
        return envelope
    }

    private static func validateGrantShape(_ grant: KDNAExternalKeyGrant) throws {
        guard grant.profile == KDNA_EXTERNAL_GRANT_PROFILE,
              grant.contract_version == KDNA_EXTERNAL_GRANT_CONTRACT_VERSION,
              grant.wrap.alg == "X25519-HKDF-SHA256+A256KW",
              grant.status_version >= 1 else {
            throw failure("KDNA_GRANT_FORMAT_INVALID", "external key grant profile is unsupported")
        }
        _ = try prefixed(grant.device_public_key, prefix: "x25519", count: 32, label: "device public key")
        _ = try prefixed(grant.device_signing_public_key, prefix: "ed25519", count: 32, label: "device signing public key")
    }

    private static func grantState(_ grant: KDNAExternalKeyGrant, now: Date, networkAvailable: Bool, allowOffline: Bool) throws -> String {
        guard let issued = parseISO8601(grant.issued_at),
              let refresh = parseISO8601(grant.refresh_after),
              let grace = parseISO8601(grant.offline_grace_until),
              let expires = parseISO8601(grant.expires_at),
              issued <= refresh, refresh <= grace, grace <= expires else {
            throw failure("KDNA_GRANT_TIME_INVALID", "grant time window is invalid")
        }
        if now.addingTimeInterval(5 * 60) < issued {
            throw failure("KDNA_GRANT_TIME_INVALID", "external key grant is not valid yet")
        }
        if grant.status == "revoked" { throw failure("KDNA_GRANT_REVOKED", "external key grant is revoked") }
        if grant.status != "active" || now > expires { throw failure("KDNA_GRANT_EXPIRED", "external key grant has expired") }
        if now <= refresh { return "active" }
        if networkAvailable { throw failure("KDNA_GRANT_SYNC_REQUIRED", "external key grant must be synchronized") }
        if !allowOffline || now > grace { throw failure("KDNA_GRANT_EXPIRED", "external key grant offline grace has expired") }
        return "offline_grace"
    }

    private static func parseISO8601(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }
        return ISO8601DateFormatter().date(from: value)
    }

    private static func canonicalSigningData(_ object: [String: Any]) throws -> Data {
        var unsigned = object
        unsigned.removeValue(forKey: "signature")
        return try JSONSerialization.data(withJSONObject: unsigned, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func strictJSONObject(_ data: Data, keys: Set<String>, code: String) throws -> [String: Any] {
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == keys else {
            throw failure(code, "JSON object has unknown or missing fields")
        }
        return value
    }

    private static func base64url(_ value: String, count: Int?, label: String) throws -> Data {
        guard value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            throw failure("KDNA_GRANT_FORMAT_INVALID", "\(label) is not canonical base64url")
        }
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64),
              data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value,
              (count == nil || data.count == count) else {
            throw failure("KDNA_GRANT_FORMAT_INVALID", "\(label) has invalid length")
        }
        return data
    }

    private static func prefixed(_ value: String, prefix: String, count: Int, label: String) throws -> Data {
        guard value.hasPrefix("\(prefix):") else {
            throw failure("KDNA_GRANT_FORMAT_INVALID", "\(label) must use \(prefix)")
        }
        return try base64url(String(value.dropFirst(prefix.count + 1)), count: count, label: label)
    }

    private static func digest(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func equal(_ actual: String, _ expected: String?, code: String, label: String) throws {
        guard let expected, actual == expected else { throw failure(code, "\(label) mismatch") }
    }

    private static func aad(manifest: [String: Any], envelope: KDNAExternalEnvelope, entryName: String) throws -> Data {
        let entitlement = manifest["entitlement"] as? [String: Any]
        let fields = [
            KDNA_EXTERNAL_ENVELOPE_PROFILE,
            KDNA_EXTERNAL_GRANT_CONTRACT_VERSION,
            manifest["asset_uid"] as? String ?? "",
            manifest["asset_id"] as? String ?? "",
            manifest["version"] as? String ?? "",
            entryName,
            envelope.plaintext_digest,
            envelope.key_ref,
            envelope.issuer_key_id,
            manifest["access"] as? String ?? "",
            entitlement?["profile"] as? String ?? "",
        ]
        guard !fields.contains(where: { $0.isEmpty }), fields[9] == "licensed", ["account", "org"].contains(fields[10]) else {
            throw failure("KDNA_ENVELOPE_BINDING_INVALID", "manifest is missing an external envelope binding")
        }
        return Data(fields.joined(separator: "\n").utf8)
    }

    private static func failure(_ code: String, _ message: String) -> KDNAExternalGrantError {
        .failure(code: code, message: message)
    }
}
