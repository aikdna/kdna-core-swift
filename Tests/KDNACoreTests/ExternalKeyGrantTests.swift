import XCTest
import CryptoKit
@testable import KDNACore

final class ExternalKeyGrantTests: XCTestCase {
    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = [Data]()
        var centralParts = [Data]()
        var offset: UInt32 = 0

        func u16(_ n: UInt16) -> Data {
            var value = n
            return Data(bytes: &value, count: 2)
        }
        func u32(_ n: UInt32) -> Data {
            var value = n
            return Data(bytes: &value, count: 4)
        }

        for (name, data) in entries {
            let nameData = Data(name.utf8)
            var local = Data()
            local.append(u32(0x04034b50))
            local.append(u16(20))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u32(0))
            local.append(u32(UInt32(data.count)))
            local.append(u32(UInt32(data.count)))
            local.append(u16(UInt16(nameData.count)))
            local.append(u16(0))
            local.append(nameData)
            local.append(data)
            localParts.append(local)

            var central = Data()
            central.append(u32(0x02014b50))
            central.append(u16(20))
            central.append(u16(20))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u32(0))
            central.append(u32(UInt32(data.count)))
            central.append(u32(UInt32(data.count)))
            central.append(u16(UInt16(nameData.count)))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u32(0))
            central.append(u32(offset))
            central.append(nameData)
            centralParts.append(central)
            offset += UInt32(local.count)
        }

        let central = centralParts.reduce(Data(), +)
        let local = localParts.reduce(Data(), +)
        var eocd = Data()
        eocd.append(u32(0x06054b50))
        eocd.append(u16(0))
        eocd.append(u16(0))
        eocd.append(u16(UInt16(entries.count)))
        eocd.append(u16(UInt16(entries.count)))
        eocd.append(u32(UInt32(central.count)))
        eocd.append(u32(UInt32(local.count)))
        eocd.append(u16(0))
        return local + central + eocd
    }

    private func fixture() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "external-grant", withExtension: "json"))
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
    }

    private func authorization(
        fixture: [String: Any],
        grantOverride: [String: Any]? = nil,
        manifestOverride: [String: Any]? = nil,
        expectedAssetDigest: String? = nil,
        issuerPublicKey: String? = nil,
        minimumStatusVersion: Int? = nil,
        minimumVerifiedTime: Date? = nil,
        now: Date = ISO8601DateFormatter().date(from: "2026-07-13T00:00:00Z")!
    ) throws -> KDNAExternalGrantAuthorization {
        let manifest = try XCTUnwrap(manifestOverride ?? fixture["manifest"] as? [String: Any])
        let keys = try XCTUnwrap(fixture["test_keys"] as? [String: String])
        let grant = try XCTUnwrap(grantOverride ?? fixture["grant"] as? [String: Any])
        let signingKeyID = try XCTUnwrap(grant["signing_key_id"] as? String)
        let grantData = try JSONSerialization.data(
            withJSONObject: grant,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let envelopeData = try XCTUnwrap(
            Data(base64URLEncoded: fixture["envelope_cbor"] as? String ?? "")
        )
        return try KDNAExternalGrantAuthorization.authorize(
            grantData: grantData,
            envelopeData: envelopeData,
            manifest: manifest,
            expectedAssetDigest: expectedAssetDigest
                ?? (fixture["expected_asset_digest"] as? String ?? ""),
            issuerPublicKeys: [signingKeyID: issuerPublicKey ?? keys["issuer_signing_public_key"]!],
            deviceAgreementPrivateKey: keys["device_agreement_private_key"]!,
            expectedAccountID: grant["account_id"] as? String ?? "",
            expectedDeviceID: grant["device_id"] as? String ?? "",
            expectedDevicePublicKey: keys["device_agreement_public_key"]!,
            expectedDeviceSigningPublicKey: keys["device_signing_public_key"]!,
            minimumStatusVersion: minimumStatusVersion,
            minimumVerifiedTime: minimumVerifiedTime,
            now: now
        )
    }

    private func signedGrant(
        fixture: [String: Any],
        assetDigest: String? = nil,
        entryPath: String? = nil,
        removeAssetField: String? = nil
    ) throws -> (value: [String: Any], publicKey: String) {
        var grant = try XCTUnwrap(fixture["grant"] as? [String: Any])
        var asset = try XCTUnwrap(grant["asset"] as? [String: Any])
        if let assetDigest { asset["digest"] = assetDigest }
        if let entryPath { asset["entry_path"] = entryPath }
        if let removeAssetField { asset.removeValue(forKey: removeAssetField) }
        grant["asset"] = asset
        grant.removeValue(forKey: "signature")

        let keys = try XCTUnwrap(fixture["test_keys"] as? [String: String])
        let root = try XCTUnwrap(Data(base64URLEncoded: keys["issuer_root"] ?? ""))
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: root)
        let canonical = try JSONSerialization.data(
            withJSONObject: grant,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let signature = try privateKey.signature(for: canonical)
        grant["signature"] = "ed25519:" + signature.base64URLEncodedString()
        return (
            grant,
            "ed25519:" + privateKey.publicKey.rawRepresentation.base64URLEncodedString()
        )
    }

    func testCurrentNodeGoldenVerifiesAndDecrypts() throws {
        let value = try fixture()
        let authorization = try authorization(fixture: value)
        XCTAssertEqual(authorization.entitlementStatus, "active")
        XCTAssertEqual(authorization.grant.profile, KDNA_EXTERNAL_GRANT_PROFILE)
        XCTAssertEqual(
            authorization.grant.contract_version,
            KDNA_EXTERNAL_GRANT_CONTRACT_VERSION
        )

        let manifest = try XCTUnwrap(value["manifest"] as? [String: Any])
        let envelope = try XCTUnwrap(
            Data(base64URLEncoded: value["envelope_cbor"] as? String ?? "")
        )
        let expected = try XCTUnwrap(
            Data(base64URLEncoded: value["plaintext_cbor"] as? String ?? "")
        )
        let plaintext = try authorization.decrypt(
            entryName: "payload.kdnab",
            envelopeData: envelope,
            manifest: manifest
        )
        XCTAssertEqual(plaintext, expected)
        let payload = try KDNACBOR.decodeObject(plaintext)
        XCTAssertEqual(payload["profile"] as? String, "kdna.payload.judgment")
        XCTAssertEqual(payload["profile_version"] as? String, "0.1.0")
    }

    func testGrantBindsPackedAssetDigestAndAssetRelease() throws {
        let value = try fixture()
        XCTAssertThrowsError(try authorization(
            fixture: value,
            expectedAssetDigest: "sha256:" + String(repeating: "0", count: 64)
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_DIGEST_MISMATCH")
        }

        var manifest = try XCTUnwrap(value["manifest"] as? [String: Any])
        manifest["version"] = "2.0.0"
        XCTAssertThrowsError(try authorization(
            fixture: value,
            manifestOverride: manifest
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_ASSET_MISMATCH")
        }
    }

    func testTamperExpiryAndRollbackFailClosed() throws {
        let value = try fixture()
        var tampered = try XCTUnwrap(value["grant"] as? [String: Any])
        tampered["account_id"] = "acct_attacker"
        XCTAssertThrowsError(try authorization(
            fixture: value,
            grantOverride: tampered
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_SIGNATURE_INVALID")
        }

        let expired = ISO8601DateFormatter().date(from: "2026-07-22T00:00:00Z")!
        XCTAssertThrowsError(try authorization(fixture: value, now: expired)) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_EXPIRED")
        }
        XCTAssertThrowsError(try authorization(
            fixture: value,
            minimumStatusVersion: 2
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_ROLLBACK_DETECTED")
        }

        let lastVerified = ISO8601DateFormatter().date(from: "2026-07-14T00:00:00Z")!
        let rolledBack = ISO8601DateFormatter().date(from: "2026-07-13T00:00:00Z")!
        XCTAssertThrowsError(try authorization(
            fixture: value,
            minimumVerifiedTime: lastVerified,
            now: rolledBack
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_AUTH_CLOCK_ROLLBACK")
        }
    }

    func testVerifiedAuthorizationOnlyReadiesItsBoundAssetRelease() throws {
        let value = try fixture()
        let manifest = try XCTUnwrap(value["manifest"] as? [String: Any])
        let envelope = try XCTUnwrap(
            Data(base64URLEncoded: value["envelope_cbor"] as? String ?? "")
        )
        let assetURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("external-grant-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: assetURL) }

        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let publishedBytes = makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("kdna.json", manifestData),
            ("payload.kdnab", envelope),
        ])
        try publishedBytes.write(to: assetURL)

        let publishedDigest = "sha256:" + SHA256.hash(data: publishedBytes)
            .map { String(format: "%02x", $0) }.joined()
        let boundGrant = try signedGrant(fixture: value, assetDigest: publishedDigest)
        let authorization = try authorization(
            fixture: value,
            grantOverride: boundGrant.value,
            expectedAssetDigest: publishedDigest,
            issuerPublicKey: boundGrant.publicKey
        )

        XCTAssertEqual(KDNARuntime.planLoad(assetURL: assetURL).state, "needs_account")
        let ready = KDNARuntime.planLoad(
            assetURL: assetURL,
            environment: KDNALoadEnvironment(externalAuthorization: authorization)
        )
        XCTAssertTrue(ready.can_load_now, ready.issues.map(\.message).joined(separator: "; "))
        XCTAssertEqual(ready.state, "ready")

        var otherManifest = manifest
        otherManifest["asset_id"] = "kdna:fixture:different"
        let otherURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("external-grant-other-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: otherURL) }
        try makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("kdna.json", try JSONSerialization.data(
                withJSONObject: otherManifest,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )),
            ("payload.kdnab", envelope),
        ]).write(to: otherURL)
        let rejected = KDNARuntime.planLoad(
            assetURL: otherURL,
            environment: KDNALoadEnvironment(externalAuthorization: authorization)
        )
        XCTAssertFalse(rejected.can_load_now)
        XCTAssertEqual(rejected.state, "invalid")
        XCTAssertTrue(rejected.issues.contains {
            $0.code == "KDNA_GRANT_ASSET_MISMATCH"
        })

        let changedBytesURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("external-grant-changed-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: changedBytesURL) }
        try makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("kdna.json", manifestData),
            ("payload.kdnab", envelope),
            ("different-container-byte", Data([0x01])),
        ]).write(to: changedBytesURL)
        let changedBytes = KDNARuntime.planLoad(
            assetURL: changedBytesURL,
            environment: KDNALoadEnvironment(externalAuthorization: authorization)
        )
        XCTAssertFalse(changedBytes.can_load_now)
        XCTAssertEqual(changedBytes.state, "invalid")
        XCTAssertTrue(changedBytes.issues.contains { $0.code == "KDNA_GRANT_DIGEST_MISMATCH" })
    }

    func testGrantEntryPathAndRequiredBindingFieldsFailClosed() throws {
        let value = try fixture()
        let wrongEntryGrant = try signedGrant(fixture: value, entryPath: "different.kdnab")
        XCTAssertThrowsError(try authorization(
            fixture: value,
            grantOverride: wrongEntryGrant.value,
            issuerPublicKey: wrongEntryGrant.publicKey
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_ASSET_MISMATCH")
        }

        let missingDigestGrant = try signedGrant(fixture: value, removeAssetField: "digest")
        XCTAssertThrowsError(try authorization(
            fixture: value,
            grantOverride: missingDigestGrant.value,
            issuerPublicKey: missingDigestGrant.publicKey
        )) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_FORMAT_INVALID")
        }
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
