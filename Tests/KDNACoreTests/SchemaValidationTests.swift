import XCTest
import CryptoKit
@testable import KDNACore

final class SchemaValidationTests: XCTestCase {
    func testBundledCanonicalSchemasHonorDigestLocksAndPinnedNodeParity() throws {
        XCTAssertEqual(
            KDNACanonicalSchemas.canonicalCommit,
            "f2f9ac4b8300413b1fda58b43fdb6d12d4545820"
        )
        for name in KDNACanonicalSchemas.expectedDigests.keys.sorted() {
            _ = try KDNACanonicalSchemas.resourceData(named: name)
        }

        // A standalone SwiftPM checkout has no sibling Node repository. CI
        // always sets this variable after checking out the pinned commit, so
        // the authoritative cross-repository byte comparison remains required
        // there while local package tests still verify every embedded SHA lock.
        guard let conformanceRoot = ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"],
              !conformanceRoot.isEmpty else { return }
        let root = URL(fileURLWithPath: conformanceRoot).appendingPathComponent("schema")
        for name in KDNACanonicalSchemas.expectedDigests.keys.sorted() {
            XCTAssertEqual(
                try KDNACanonicalSchemas.resourceData(named: name),
                try Data(contentsOf: root.appendingPathComponent(name)),
                "Bundled \(name) drifted from canonical Node schema."
            )
        }
    }

    func testAJVGeneratedFormatBoundariesMatchSwift() throws {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "schema-format-ajv-v1",
            withExtension: "json"
        ))
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        XCTAssertEqual(fixture["canonical_commit"] as? String, KDNACanonicalSchemas.canonicalCommit)
        for format in ["date-time", "uri"] {
            let cases = try XCTUnwrap(fixture[format] as? [[String: Any]])
            for item in cases {
                let value = try XCTUnwrap(item["value"] as? String)
                let expected = try XCTUnwrap(item["valid"] as? Bool)
                let actual = format == "date-time"
                    ? KDNAJSONFormats.isDateTime(value)
                    : KDNAJSONFormats.isURI(value)
                XCTAssertEqual(actual, expected, "AJV \(format) parity failed for \(value)")
            }
        }
    }

    func testManifestSchemaEnforcesEveryRequiredPropertyAndNestedContracts() {
        let manifest = validManifest()
        XCTAssertTrue(KDNACanonicalSchemas.validateManifest(manifest).isEmpty)

        let required = [
            "kdna_version", "asset_id", "asset_uid", "asset_type", "title",
            "version", "judgment_version", "created_at", "updated_at",
            "compatibility", "payload",
        ]
        for key in required {
            var candidate = manifest
            candidate.removeValue(forKey: key)
            XCTAssertFalse(
                KDNACanonicalSchemas.validateManifest(candidate).isEmpty,
                "Missing required manifest property was accepted: \(key)"
            )
        }

        var emptyTitle = manifest
        emptyTitle["title"] = ""
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(emptyTitle).isEmpty)

        var badCreator = manifest
        badCreator["creator"] = ["creator_type": "human"]
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(badCreator).isEmpty)

        var badPayload = manifest
        badPayload["payload"] = ["path": "other", "encoding": "json", "encrypted": "no"]
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(badPayload).isEmpty)

        var badProfiles = manifest
        var contract = validLoadContract()
        var profiles = contract["profiles"] as! [String: Any]
        profiles.removeValue(forKey: "full")
        profiles["future"] = [:]
        contract["profiles"] = profiles
        badProfiles["load_contract"] = contract
        let profileIssues = KDNACanonicalSchemas.validateManifest(badProfiles)
        XCTAssertTrue(profileIssues.contains { $0.contains("full") })
        XCTAssertTrue(profileIssues.contains { $0.contains("future") })

        var badReferenceTarget = manifest
        contract = validLoadContract()
        profiles = contract["profiles"] as! [String: Any]
        profiles["compact"] = ["max_tokens_hint": -1]
        contract["profiles"] = profiles
        badReferenceTarget["load_contract"] = contract
        XCTAssertTrue(
            KDNACanonicalSchemas.validateManifest(badReferenceTarget)
                .contains { $0.contains("max_tokens_hint") }
        )

        var nonIntegerHint = manifest
        contract = validLoadContract()
        profiles = contract["profiles"] as! [String: Any]
        profiles["compact"] = ["max_tokens_hint": 0.5]
        contract["profiles"] = profiles
        nonIntegerHint["load_contract"] = contract
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(nonIntegerHint).isEmpty)

        var badAdditionalSchema = manifest
        badAdditionalSchema["dependencies"] = ["@aikdna/base": 7]
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(badAdditionalSchema).isEmpty)
    }

    func testPayloadSchemaEnforcesRequiredAndNestedShapes() {
        let payload = validPayload()
        XCTAssertTrue(KDNACanonicalSchemas.validatePayload(payload).isEmpty)

        for key in ["profile", "core"] {
            var candidate = payload
            candidate.removeValue(forKey: key)
            XCTAssertFalse(KDNACanonicalSchemas.validatePayload(candidate).isEmpty)
        }
        for key in ["highest_question", "axioms"] {
            var candidate = payload
            var core = candidate["core"] as! [String: Any]
            core.removeValue(forKey: key)
            candidate["core"] = core
            XCTAssertFalse(KDNACanonicalSchemas.validatePayload(candidate).isEmpty)
        }

        var badWorldview = payload
        var core = badWorldview["core"] as! [String: Any]
        core["worldview"] = ["valid", 7] as [Any]
        badWorldview["core"] = core
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(badWorldview).isEmpty)

        var badSelfCheck = payload
        badSelfCheck["reasoning"] = ["self_check": [["failure_risk": "missing question"]]]
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(badSelfCheck).isEmpty)

        var badEvolution = payload
        badEvolution["evolution"] = ["version_notes": ["ok", 1] as [Any]]
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(badEvolution).isEmpty)
    }

    func testLoadPlanAndCapsuleFailClosedOnFormalSchemaViolations() throws {
        let invalidManifestBytes = try mutatedGolden { manifest, _ in
            manifest["title"] = ""
        }
        let manifestPlan = KDNALoadPlanCore.planLoad(assetData: invalidManifestBytes)
        XCTAssertFalse(manifestPlan.checks.schema_valid)
        XCTAssertFalse(manifestPlan.can_load_now)
        XCTAssertThrowsError(try KDNACapsuleV2.load(assetData: invalidManifestBytes))

        let invalidPayloadBytes = try mutatedGolden { _, payload in
            var core = payload["core"] as! [String: Any]
            core["worldview"] = [1]
            payload["core"] = core
        }
        let payloadPlan = KDNALoadPlanCore.planLoad(assetData: invalidPayloadBytes)
        XCTAssertFalse(payloadPlan.checks.payload_valid)
        XCTAssertFalse(payloadPlan.can_load_now)
        XCTAssertThrowsError(try KDNACapsuleV2.load(assetData: invalidPayloadBytes))

        let invalidLoadContractBytes = try mutatedGolden { manifest, _ in
            var contract = manifest["load_contract"] as! [String: Any]
            var profiles = contract["profiles"] as! [String: Any]
            profiles.removeValue(forKey: "full")
            contract["profiles"] = profiles
            manifest["load_contract"] = contract
        }
        let contractPlan = KDNALoadPlanCore.planLoad(assetData: invalidLoadContractBytes)
        XCTAssertFalse(contractPlan.checks.schema_valid)
        XCTAssertFalse(contractPlan.checks.load_contract_valid)
        XCTAssertFalse(contractPlan.can_load_now)

        for invalidURI in [
            "https://example.com:１２/path",
            "https://example.com:١٢/path",
            "Kttps://example.com",
            "https://example.Kom",
            "ſttps://example.com",
        ] {
            let bytes = try mutatedGolden { manifest, _ in
                manifest["asset_uid"] = invalidURI
            }
            let plan = KDNALoadPlanCore.planLoad(assetData: bytes)
            XCTAssertFalse(plan.checks.schema_valid, "Invalid AJV URI was schema-valid: \(invalidURI)")
            XCTAssertFalse(plan.can_load_now)
        }

        for invalidDate in [
            "2026-07-15\u{0085}12:34:56Z",
            "2026-07-15ſ12:34:56Z",
        ] {
            let bytes = try mutatedGolden { manifest, _ in
                manifest["created_at"] = invalidDate
            }
            let plan = KDNALoadPlanCore.planLoad(assetData: bytes)
            XCTAssertFalse(plan.checks.schema_valid, "Invalid AJV date-time was schema-valid.")
            XCTAssertFalse(plan.can_load_now)
        }

        let validFEFFDateBytes = try mutatedGolden { manifest, _ in
            manifest["created_at"] = "2026-07-15\u{FEFF}12:34:56Z"
            manifest["updated_at"] = "2026-07-15\u{FEFF}12:34:56Z"
        }
        let validFEFFPlan = KDNALoadPlanCore.planLoad(assetData: validFEFFDateBytes)
        XCTAssertTrue(validFEFFPlan.checks.schema_valid, validFEFFPlan.issues.map(\.message).joined(separator: "\n"))
        XCTAssertTrue(validFEFFPlan.can_load_now)
        let validFEFFCapsule = try KDNACapsuleV2.load(assetData: validFEFFDateBytes)
        XCTAssertTrue(validFEFFCapsule.trace.schema_valid)
    }

    func testGenericDigestEvidenceRoundTripsUnavailableNullObservation() throws {
        let unavailable = KDNADigestComparison(
            state: "unavailable",
            against: nil,
            expected: nil,
            source: nil
        )
        let evidence = KDNADigestEvidence(
            profile: "kdna-capsule-digests-v1",
            asset: KDNADigestObservation(
                value: nil,
                basis: "kdna-container-bytes-v1",
                comparison: unavailable
            ),
            content: KDNADigestObservation(
                value: nil,
                basis: "kdna-content-tree-v1",
                comparison: unavailable
            ),
            runtime_entry_set: KDNADigestObservation(
                value: nil,
                basis: "kdna-runtime-entry-set-v1",
                comparison: unavailable
            )
        )
        let encoded = try JSONEncoder().encode(evidence)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let asset = try XCTUnwrap(object["asset"] as? [String: Any])
        XCTAssertTrue(asset["value"] is NSNull)
        XCTAssertEqual(try JSONDecoder().decode(KDNADigestEvidence.self, from: encoded), evidence)
    }

    private func validManifest() -> [String: Any] {
        [
            "kdna_version": "1.0",
            "asset_id": "kdna:test:schema",
            "asset_uid": "urn:uuid:00190000-0000-4000-8000-000000000001",
            "asset_type": "fixture",
            "title": "Schema Fixture",
            "version": "1.0.0",
            "judgment_version": "1.0.0",
            "created_at": "2026-07-15T00:00:00Z",
            "updated_at": "2026-07-15T00:00:00Z",
            "compatibility": ["min_loader_version": "0.16.0", "profile": "judgment-profile-v1"],
            "payload": ["path": "payload.kdnab", "encoding": "cbor", "encrypted": false],
            "load_contract": validLoadContract(),
        ]
    }

    private func validLoadContract() -> [String: Any] {
        [
            "default_profile": "compact",
            "profiles": [
                "index": ["max_tokens_hint": 0],
                "compact": ["max_tokens_hint": 512],
                "scenario": ["selection": "scenario"],
                "full": ["intended_for": ["audit"]],
            ],
        ]
    }

    private func validPayload() -> [String: Any] {
        [
            "profile": "judgment-profile-v1",
            "core": [
                "highest_question": "Does formal schema validation hold?",
                "worldview": ["Validation is evidence."],
                "axioms": [] as [Any],
            ] as [String: Any],
            "reasoning": ["self_check": [["question": "Was every ref followed?"]]],
        ]
    }

    private func mutatedGolden(
        _ mutate: (inout [String: Any], inout [String: Any]) -> Void
    ) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/capsule-v2-minimal.kdna.b64")
        let encoded = try String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let original = try XCTUnwrap(Data(base64Encoded: encoded))
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: original)
        var manifest = try XCTUnwrap(reader.readManifest(asset: asset))
        var payload = try KDNACBOR.decodeObject(reader.readEntry(asset: asset, name: "payload.kdnab"))
        mutate(&manifest, &payload)
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let payloadData = try KDNACBOR.encode(payload)
        let entrySetDigest = KDNAChecksumDigests.computeRuntimeEntrySetDigest(
            manifest: manifestData,
            payload: payloadData
        )
        let checksums = try JSONSerialization.data(withJSONObject: [
            "algorithm": "sha256",
            "digest_profile": "kdna-runtime-entry-set-v1",
            "covered_entries": ["kdna.json", "payload.kdnab"],
            "manifest_digest": "sha256:\(sha256Hex(manifestData))",
            "payload_digest": "sha256:\(sha256Hex(payloadData))",
            "entry_set_digest": entrySetDigest,
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        return makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("checksums.json", checksums),
            ("kdna.json", manifestData),
            ("payload.kdnab", payloadData),
        ])
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = [Data]()
        var centralParts = [Data]()
        var offset: UInt32 = 0
        func u16(_ number: UInt16) -> Data { var value = number; return Data(bytes: &value, count: 2) }
        func u32(_ number: UInt32) -> Data { var value = number; return Data(bytes: &value, count: 4) }
        for (name, data) in entries {
            let nameData = Data(name.utf8)
            var local = Data()
            local.append(u32(0x04034b50)); local.append(u16(20)); local.append(u16(0)); local.append(u16(0))
            local.append(u16(0)); local.append(u16(0)); local.append(u32(0)); local.append(u32(UInt32(data.count)))
            local.append(u32(UInt32(data.count))); local.append(u16(UInt16(nameData.count))); local.append(u16(0))
            local.append(nameData); local.append(data); localParts.append(local)
            var central = Data()
            central.append(u32(0x02014b50)); central.append(u16(20)); central.append(u16(20)); central.append(u16(0))
            central.append(u16(0)); central.append(u16(0)); central.append(u16(0)); central.append(u32(0))
            central.append(u32(UInt32(data.count))); central.append(u32(UInt32(data.count)))
            central.append(u16(UInt16(nameData.count))); central.append(u16(0)); central.append(u16(0))
            central.append(u16(0)); central.append(u16(0)); central.append(u32(0)); central.append(u32(offset))
            central.append(nameData); centralParts.append(central); offset += UInt32(local.count)
        }
        let local = localParts.reduce(Data(), +)
        let central = centralParts.reduce(Data(), +)
        var end = Data()
        end.append(u32(0x06054b50)); end.append(u16(0)); end.append(u16(0)); end.append(u16(UInt16(entries.count)))
        end.append(u16(UInt16(entries.count))); end.append(u32(UInt32(central.count)))
        end.append(u32(UInt32(local.count))); end.append(u16(0))
        return local + central + end
    }

}
