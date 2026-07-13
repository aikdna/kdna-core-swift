import XCTest
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
        let url = try XCTUnwrap(Bundle.module.url(forResource: "external-grant-v1", withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func authorization(
        fixture: [String: Any],
        grantOverride: [String: Any]? = nil,
        minimumStatusVersion: Int? = nil,
        minimumVerifiedTime: Date? = nil,
        now: Date = ISO8601DateFormatter().date(from: "2026-07-13T12:00:00Z")!
    ) throws -> KDNAExternalGrantAuthorization {
        let manifest = try XCTUnwrap(fixture["manifest"] as? [String: Any])
        let checksums = try XCTUnwrap(fixture["checksums"] as? [String: Any])
        let keys = try XCTUnwrap(fixture["test_keys"] as? [String: String])
        let grant = try XCTUnwrap(grantOverride ?? fixture["grant"] as? [String: Any])
        let grantData = try JSONSerialization.data(withJSONObject: grant, options: [.sortedKeys, .withoutEscapingSlashes])
        let envelopeData = try XCTUnwrap(Data(base64URLEncoded: fixture["envelope_cbor"] as? String ?? ""))
        return try KDNAExternalGrantAuthorization.authorize(
            grantData: grantData,
            envelopeData: envelopeData,
            manifest: manifest,
            checksums: checksums,
            issuerPublicKeys: ["fixture-grant-signing-v1": keys["issuer_signing_public_key"]!],
            deviceAgreementPrivateKey: keys["device_agreement_private_key"]!,
            expectedAccountID: "acct_fixture_01",
            expectedDeviceID: "dev_fixture_01",
            expectedDevicePublicKey: keys["device_agreement_public_key"]!,
            expectedDeviceSigningPublicKey: keys["device_signing_public_key"]!,
            minimumStatusVersion: minimumStatusVersion,
            minimumVerifiedTime: minimumVerifiedTime,
            now: now
        )
    }

    func testDecryptsJavaScriptGoldenVector() throws {
        let value = try fixture()
        let authorization = try authorization(fixture: value)
        XCTAssertEqual(authorization.entitlementStatus, "active")
        let manifest = try XCTUnwrap(value["manifest"] as? [String: Any])
        let envelope = try XCTUnwrap(Data(base64URLEncoded: value["envelope_cbor"] as? String ?? ""))
        let expected = try XCTUnwrap(Data(base64URLEncoded: value["plaintext_cbor"] as? String ?? ""))
        let plaintext = try authorization.decrypt(entryName: "payload.kdnab", envelopeData: envelope, manifest: manifest)
        XCTAssertEqual(plaintext, expected)
        XCTAssertEqual(try KDNACBOR.decodeObject(plaintext)["profile"] as? String, "judgment-profile-v1")
    }

    func testTamperAndExpiryFailClosed() throws {
        let value = try fixture()
        var tampered = try XCTUnwrap(value["grant"] as? [String: Any])
        tampered["account_id"] = "acct_attacker"
        XCTAssertThrowsError(try authorization(fixture: value, grantOverride: tampered)) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_SIGNATURE_INVALID")
        }
        let expired = ISO8601DateFormatter().date(from: "2026-07-22T00:00:00Z")!
        XCTAssertThrowsError(try authorization(fixture: value, now: expired)) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_EXPIRED")
        }
    }

    func testStatusRollbackFailsClosed() throws {
        let value = try fixture()
        XCTAssertThrowsError(try authorization(fixture: value, minimumStatusVersion: 2)) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_GRANT_ROLLBACK_DETECTED")
        }
        let lastVerified = ISO8601DateFormatter().date(from: "2026-07-14T00:00:00Z")!
        let rolledBack = ISO8601DateFormatter().date(from: "2026-07-13T00:00:00Z")!
        XCTAssertThrowsError(try authorization(fixture: value, minimumVerifiedTime: lastVerified, now: rolledBack)) { error in
            XCTAssertEqual((error as? KDNAExternalGrantError)?.code, "KDNA_AUTH_CLOCK_ROLLBACK")
        }
    }

    func testVerifiedAuthorizationDrivesLoadPlanAndCapsule() throws {
        let value = try fixture()
        let authorization = try authorization(fixture: value)
        let manifest = try XCTUnwrap(value["manifest"] as? [String: Any])
        let envelope = try XCTUnwrap(Data(base64URLEncoded: value["envelope_cbor"] as? String ?? ""))
        let assetURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("external-grant-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: assetURL) }
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        try makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("kdna.json", manifestData),
            ("payload.kdnab", envelope),
        ]).write(to: assetURL)

        XCTAssertEqual(KDNARuntime.planLoad(assetURL: assetURL).state, "needs_account")
        let ready = KDNARuntime.planLoad(
            assetURL: assetURL,
            environment: KDNALoadEnvironment(externalAuthorization: authorization)
        )
        XCTAssertTrue(ready.can_load_now)
        XCTAssertEqual(ready.state, "ready")
        let capsule = try KDNARuntime.load(
            assetURL: assetURL,
            credential: KDNACredential(externalAuthorization: authorization),
            profile: "compact"
        )
        XCTAssertEqual(capsule.type, "kdna.context.capsule")
        XCTAssertEqual(capsule.domain, "@fixture/external-grant")
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
