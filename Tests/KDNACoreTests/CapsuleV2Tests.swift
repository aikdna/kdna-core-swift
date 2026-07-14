import XCTest
import CryptoKit
@testable import KDNACore

final class CapsuleV2Tests: XCTestCase {
    private let expectedA = "sha256:936afdde43ff207fa7570cf1524f36d89ad2b6b95f0a5811ba0d985878121d6e"
    private let expectedC = "sha256:07517fae8ad821c71829f9f802b4fd85a3227c5557efa7485ad0f9b091a3e2b2"
    private let expectedE = "sha256:c64dfa87b9599629f8b618310a9eaf1bacac3a8660a05d89c94515db0435ddfc"
    private let expectedP = "sha256:50bf805cd7e39a7dfb96c08df16dc5ff1c691af809a1035de750258cfbb996e4"
    private let loadedAt = "2026-07-15T00:00:00.000Z"

    func testNodeGoldenFreezesACEPCapsuleAndAdapterBytes() throws {
        let bytes = try goldenBytes()
        let evidence = try KDNACapsuleV2.computeDigestEvidence(assetData: bytes)

        XCTAssertEqual(evidence.asset.value, expectedA)
        XCTAssertEqual(evidence.content.value, expectedC)
        XCTAssertEqual(evidence.runtime_entry_set.value, expectedE)
        XCTAssertEqual(evidence.asset.comparison.state, "not_compared")
        XCTAssertEqual(evidence.content.comparison.state, "not_compared")
        XCTAssertEqual(evidence.runtime_entry_set.comparison.state, "matched")
        XCTAssertEqual(
            evidence.runtime_entry_set.comparison.source,
            "checksums.json.asset_digest"
        )

        let capsule = try KDNARuntime.loadV2(
            assetData: bytes,
            profile: "compact",
            loadedAt: loadedAt
        )
        XCTAssertEqual(capsule.type, "kdna.context.capsule")
        XCTAssertEqual(capsule.version, "2.0")
        XCTAssertEqual(capsule.asset.asset_id, "kdna:example:agent-project-context")
        XCTAssertEqual(capsule.asset.asset_uid, "urn:uuid:00000000-0000-4000-8000-000000000001")
        XCTAssertEqual(capsule.asset.version, "1.0.0")
        XCTAssertEqual(capsule.asset.judgment_version, "1.0.0")
        XCTAssertEqual(capsule.digests, evidence)
        XCTAssertEqual(capsule.signature.state, "absent")
        XCTAssertNil(capsule.signature.issuer)
        XCTAssertEqual(capsule.access, "public")
        XCTAssertNil(capsule.risk_level)
        XCTAssertEqual(capsule.trace.loaded_by, "kdna-core")
        XCTAssertEqual(capsule.trace.loaded_at, loadedAt)
        XCTAssertEqual(capsule.trace.input_kind, "packaged_bytes")
        XCTAssertTrue(capsule.trace.runtime_eligible)
        XCTAssertTrue(capsule.trace.schema_valid)
        XCTAssertNil(capsule.compatibility)
        XCTAssertEqual(
            capsule.context["highest_question"]?.stringValue,
            "What does this minimal example demonstrate?"
        )
        XCTAssertEqual(capsule.context["worldview"]?.arrayValue, [])
        XCTAssertEqual(capsule.context["value_order"]?.arrayValue, [])
        XCTAssertEqual(capsule.context["judgment_role"], .null)
        XCTAssertEqual(try KDNACapsuleV2.computeDeliveryDigest(capsule), expectedP)

        let encoded = try JSONEncoder().encode(capsule)
        let encodedObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertTrue(encodedObject["risk_level"] is NSNull)
        let encodedDigests = try XCTUnwrap(encodedObject["digests"] as? [String: Any])
        let encodedAsset = try XCTUnwrap(encodedDigests["asset"] as? [String: Any])
        let encodedComparison = try XCTUnwrap(encodedAsset["comparison"] as? [String: Any])
        XCTAssertTrue(encodedComparison.keys.contains("against"))
        XCTAssertTrue(encodedComparison["against"] is NSNull)
        XCTAssertEqual(try JSONDecoder().decode(KDNAContextCapsule2.self, from: encoded), capsule)

        let capsule1 = try KDNACapsuleV2.adaptToV1(capsule)
        let direct = try KDNALoadPlanCore.loadCapsule(
            assetData: bytes,
            sourcePath: "<packaged-bytes>",
            profile: "compact",
            loadedAt: loadedAt
        )
        XCTAssertEqual(capsule1, direct)
        XCTAssertEqual(capsule1.version, "1.0")
        XCTAssertEqual(capsule1.domain, capsule.asset.asset_id)
        XCTAssertEqual(capsule1.judgment_version, capsule.asset.judgment_version)
        XCTAssertEqual(capsule1.asset_digest, expectedE)
        XCTAssertNotEqual(capsule1.asset_digest, expectedA)
        XCTAssertEqual(capsule1.context, capsule.context)
        XCTAssertEqual(capsule1.trace.loaded_by, "kdna-core")
        XCTAssertEqual(capsule1.trace.loaded_at, loadedAt)
        let capsule1Object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(capsule1)) as? [String: Any]
        )
        XCTAssertTrue(capsule1Object["risk_level"] is NSNull)
    }

    func testJCSMatchesRFC8785AppendixBNumbers() throws {
        let vectors: [(UInt64, String)] = [
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ]

        for (bits, expected) in vectors {
            XCTAssertEqual(
                try KDNAJCS.canonicalString(.number(Double(bitPattern: bits))),
                expected,
                String(format: "%016llx", bits)
            )
        }
    }

    func testJCSUsesUTF16KeysAndStrictJSONPrimitives() throws {
        let vector: KDNAJSONValue = .object([
            "\u{E000}": .string("bmp"),
            "\u{10000}": .string("astral"),
            "minusZero": .number(-0.0),
            "small": .number(1e-7),
        ])
        XCTAssertEqual(
            try KDNAJCS.canonicalString(vector),
            "{\"minusZero\":0,\"small\":1e-7,\"\u{10000}\":\"astral\",\"\u{E000}\":\"bmp\"}"
        )
        XCTAssertEqual(
            try KDNAJCS.canonicalString(.object([
                "literals": .array([.null, .bool(true), .bool(false)]),
                "numbers": .array([
                    .number(333333333.33333329), .number(1e30), .number(4.5),
                    .number(2e-3), .number(1e-27),
                ]),
            ])),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"
        )
        XCTAssertEqual(
            try KDNAJCS.canonicalString(.object(["string": .string("\u{000f}\n\"\\€")])),
            "{\"string\":\"\\u000f\\n\\\"\\\\€\"}"
        )
        XCTAssertThrowsError(try KDNAJCS.canonicalString(.number(.nan))) { error in
            XCTAssertEqual((error as? KDNACapsule2Error)?.code, "KDNA_JCS_NON_FINITE_NUMBER")
        }
        XCTAssertThrowsError(try KDNAJCS.canonicalString(.number(.infinity))) { error in
            XCTAssertEqual((error as? KDNACapsule2Error)?.code, "KDNA_JCS_NON_FINITE_NUMBER")
        }
    }

    func testContentEntryPathsUseUTF8ByteOrder() throws {
        let bmp = "\u{E000}.txt"
        let astral = "\u{10000}.txt"
        let bmpData = Data("bmp".utf8)
        let astralData = Data("astral".utf8)
        XCTAssertTrue(bmp.utf8.lexicographicallyPrecedes(astral.utf8))
        XCTAssertTrue(astral.utf16.lexicographicallyPrecedes(bmp.utf16))

        let lines = [
            "\(bmp):\(sha256Hex(bmpData))",
            "\(astral):\(sha256Hex(astralData))",
        ].joined(separator: "\n")
        let expected = "sha256:\(sha256Hex(Data(lines.utf8)))"
        XCTAssertEqual(
            try KDNAContentDigest.computeValidated(files: [
                astral: "astral",
                bmp: "bmp",
            ]),
            expected
        )
    }

    func testExternalACEMismatchesFailClosedWithStableCodes() throws {
        let bytes = try goldenBytes()
        let wrong = "sha256:" + String(repeating: "0", count: 64)
        let cases: [(KDNAExpectedDigests, String)] = [
            (KDNAExpectedDigests(asset: KDNAExpectedDigest(value: wrong, source: "install_receipt")),
             "KDNA_ASSET_DIGEST_MISMATCH"),
            (KDNAExpectedDigests(content: KDNAExpectedDigest(value: wrong, source: "install_receipt")),
             "KDNA_CONTENT_DIGEST_MISMATCH"),
            (KDNAExpectedDigests(runtime_entry_set: KDNAExpectedDigest(value: wrong, source: "install_receipt")),
             "KDNA_RUNTIME_ENTRY_SET_DIGEST_MISMATCH"),
        ]

        for (expected, code) in cases {
            XCTAssertThrowsError(try KDNACapsuleV2.load(
                assetData: bytes,
                expected: expected,
                loadedAt: loadedAt
            )) { error in
                XCTAssertEqual((error as? KDNACapsule2Error)?.code, code)
            }
        }

        XCTAssertThrowsError(try KDNACapsuleV2.computeDigestEvidence(
            assetData: bytes,
            expected: KDNAExpectedDigests(asset: KDNAExpectedDigest(
                value: expectedA,
                source: "kdna.json.content_digest"
            ))
        )) { error in
            XCTAssertEqual((error as? KDNACapsule2Error)?.code, "KDNA_DIGEST_EXPECTATION_INVALID")
        }
    }

    func testNoChecksumsStillComputesEAndAdapterParity() throws {
        let bytes = try goldenBytes()
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: bytes)
        let noChecksums = makeZip(entries: [
            ("mimetype", try reader.readEntry(asset: asset, name: "mimetype")),
            ("kdna.json", try reader.readEntry(asset: asset, name: "kdna.json")),
            ("payload.kdnab", try reader.readEntry(asset: asset, name: "payload.kdnab")),
        ])

        let evidence = try KDNACapsuleV2.computeDigestEvidence(assetData: noChecksums)
        XCTAssertEqual(evidence.runtime_entry_set.value, expectedE)
        XCTAssertEqual(evidence.runtime_entry_set.comparison.state, "not_compared")
        let capsule2 = try KDNACapsuleV2.load(assetData: noChecksums, loadedAt: loadedAt)
        let capsule1 = try KDNACapsuleV2.adaptToV1(capsule2)
        XCTAssertEqual(capsule1.asset_digest, expectedE)
        XCTAssertEqual(capsule2.digests.runtime_entry_set.value, expectedE)
    }

    func testDomainAccessAndExtensionsSurviveAdapterWithoutV2Authority() throws {
        let bytes = try goldenBytes()
        let base = try KDNACapsuleV2.load(assetData: bytes, loadedAt: loadedAt)
        let direct = try KDNACapsuleV2.adaptToV1(base)
        let capsule1 = KDNAContextCapsule(
            type: direct.type,
            version: direct.version,
            domain: "@legacy/editorial",
            judgment_version: direct.judgment_version,
            asset_digest: direct.asset_digest,
            signature: direct.signature,
            access: "open",
            risk_level: direct.risk_level,
            profile: direct.profile,
            context: direct.context,
            trace: direct.trace,
            extends_chain: .array([.object(["name": .string("@example/base")])]),
            inheritance_applied: true,
            resolved_dependencies: .array([.object(["status": .string("loaded")])]),
            rag_isolation_policy: .object(["default": .string("fenced")])
        )
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: bytes)
        var manifest = try XCTUnwrap(reader.readManifest(asset: asset))
        manifest["name"] = "@legacy/editorial"
        manifest["access"] = "open"
        let capsule2 = try KDNACapsuleV2.build(
            capsule1: capsule1,
            manifest: manifest,
            digests: base.digests,
            inputKind: "packaged_bytes",
            loadedAt: loadedAt
        )

        XCTAssertEqual(capsule2.asset.asset_id, base.asset.asset_id)
        XCTAssertEqual(capsule2.access, "public")
        XCTAssertEqual(capsule2.compatibility?.capsule_1_domain, "@legacy/editorial")
        XCTAssertEqual(capsule2.compatibility?.capsule_1_access, "open")
        XCTAssertEqual(capsule2.compatibility?.capsule_1_extensions?.extends_chain, capsule1.extends_chain)
        XCTAssertEqual(try KDNACapsuleV2.adaptToV1(capsule2), capsule1)

        let invalid = KDNAContextCapsule2(
            asset: capsule2.asset,
            digests: capsule2.digests,
            signature: capsule2.signature,
            access: "licensed",
            risk_level: capsule2.risk_level,
            profile: capsule2.profile,
            context: capsule2.context,
            trace: capsule2.trace,
            compatibility: capsule2.compatibility
        )
        XCTAssertThrowsError(try KDNACapsuleV2.adaptToV1(invalid)) { error in
            XCTAssertEqual((error as? KDNACapsule2Error)?.code, "KDNA_CAPSULE_ADAPTER_INPUT_INVALID")
        }
    }

    func testRealLegacyAccessAliasesPreserveDirectWireAndAdapterParity() throws {
        let canonicalByAlias = [
            "open": "public",
            "protected": "licensed",
            "runtime": "remote",
        ]
        for alias in ["open", "protected"] {
            let bytes = try assetBytes(access: alias)
            let credential = alias == "protected"
                ? KDNACredential(password: "legacy-access-presence")
                : .none
            let environment = KDNALoadEnvironment(hasPassword: alias == "protected")
            let plan = KDNALoadPlanCore.planLoad(
                assetData: bytes,
                sourcePath: "<\(alias)-asset>",
                environment: environment
            )
            XCTAssertEqual(plan.access, canonicalByAlias[alias])
            XCTAssertEqual(plan.access_alias, alias)
            XCTAssertTrue(plan.can_load_now)

            let direct = try KDNALoadPlanCore.loadCapsule(
                assetData: bytes,
                sourcePath: "<\(alias)-asset>",
                credential: credential,
                loadedAt: loadedAt
            )
            let capsule2 = try KDNACapsuleV2.load(
                assetData: bytes,
                credential: credential,
                loadedAt: loadedAt
            )
            XCTAssertEqual(direct.access, alias)
            XCTAssertEqual(capsule2.access, canonicalByAlias[alias])
            XCTAssertEqual(capsule2.compatibility?.capsule_1_access, alias)
            XCTAssertEqual(try KDNACapsuleV2.adaptToV1(capsule2), direct)
        }

        // A runtime alias is a real remote access path. It must preserve its
        // spelling and mapping, but local loading remains blocked until a
        // Runtime endpoint supplies the projection.
        let runtimeBytes = try assetBytes(access: "runtime")
        let runtimePlan = KDNALoadPlanCore.planLoad(
            assetData: runtimeBytes,
            sourcePath: "<runtime-asset>"
        )
        XCTAssertEqual(runtimePlan.access, "remote")
        XCTAssertEqual(runtimePlan.access_alias, "runtime")
        XCTAssertEqual(runtimePlan.state, "needs_runtime")
        XCTAssertFalse(runtimePlan.can_load_now)
        XCTAssertThrowsError(try KDNACapsuleV2.load(assetData: runtimeBytes, loadedAt: loadedAt))

        let publicDirect = try KDNALoadPlanCore.loadCapsule(
            assetData: try goldenBytes(),
            sourcePath: "<packaged-bytes>",
            loadedAt: loadedAt
        )
        let reader = KDNAAssetReader()
        let runtimeAsset = try reader.open(data: runtimeBytes)
        let runtimeManifest = try XCTUnwrap(reader.readManifest(asset: runtimeAsset))
        let runtimeEvidence = try KDNACapsuleV2.computeDigestEvidence(assetData: runtimeBytes)
        let runtimeDirect = capsule1ReplacingAccess(
            publicDirect,
            access: "runtime",
            assetDigest: runtimeEvidence.runtime_entry_set.value
        )
        let runtimeCapsule2 = try KDNACapsuleV2.build(
            capsule1: runtimeDirect,
            manifest: runtimeManifest,
            digests: runtimeEvidence,
            inputKind: "packaged_bytes",
            loadedAt: loadedAt
        )
        XCTAssertEqual(runtimeCapsule2.access, "remote")
        XCTAssertEqual(runtimeCapsule2.compatibility?.capsule_1_access, "runtime")
        XCTAssertEqual(try KDNACapsuleV2.adaptToV1(runtimeCapsule2), runtimeDirect)
    }

    func testStrictCodableRejectsMissingRequiredNullAndUnknownProperties() throws {
        let capsule2 = try KDNACapsuleV2.load(assetData: goldenBytes(), loadedAt: loadedAt)
        let capsule2Object = try jsonObject(JSONEncoder().encode(capsule2))

        var missingRisk = capsule2Object
        missingRisk.removeValue(forKey: "risk_level")
        XCTAssertThrowsError(try decodeCapsule2(missingRisk))

        var unknownTop = capsule2Object
        unknownTop["asset_digest"] = expectedE
        XCTAssertThrowsError(try decodeCapsule2(unknownTop))

        var unknownNested = capsule2Object
        var trace = try XCTUnwrap(unknownNested["trace"] as? [String: Any])
        trace["host_claim"] = "not-observed"
        unknownNested["trace"] = trace
        XCTAssertThrowsError(try decodeCapsule2(unknownNested))

        var nullOptional = capsule2Object
        nullOptional["compatibility"] = NSNull()
        XCTAssertThrowsError(try decodeCapsule2(nullOptional))

        var nullIssuer = capsule2Object
        var signature = try XCTUnwrap(nullIssuer["signature"] as? [String: Any])
        signature["issuer"] = NSNull()
        nullIssuer["signature"] = signature
        XCTAssertThrowsError(try decodeCapsule2(nullIssuer))

        var missingComparisonNull = capsule2Object
        var digests = try XCTUnwrap(missingComparisonNull["digests"] as? [String: Any])
        var asset = try XCTUnwrap(digests["asset"] as? [String: Any])
        var comparison = try XCTUnwrap(asset["comparison"] as? [String: Any])
        comparison.removeValue(forKey: "against")
        asset["comparison"] = comparison
        digests["asset"] = asset
        missingComparisonNull["digests"] = digests
        XCTAssertThrowsError(try decodeCapsule2(missingComparisonNull))

        var unavailableSuccess = capsule2Object
        var unavailableDigests = try XCTUnwrap(unavailableSuccess["digests"] as? [String: Any])
        var unavailableAsset = try XCTUnwrap(unavailableDigests["asset"] as? [String: Any])
        var unavailableComparison = try XCTUnwrap(unavailableAsset["comparison"] as? [String: Any])
        unavailableAsset["value"] = NSNull()
        unavailableComparison["state"] = "unavailable"
        unavailableComparison["against"] = NSNull()
        unavailableComparison["expected"] = NSNull()
        unavailableComparison["source"] = NSNull()
        unavailableAsset["comparison"] = unavailableComparison
        unavailableDigests["asset"] = unavailableAsset
        unavailableSuccess["digests"] = unavailableDigests
        XCTAssertThrowsError(try decodeCapsule2(unavailableSuccess))

        XCTAssertEqual(try decodeCapsule2(capsule2Object), capsule2)

        let capsule1 = try KDNACapsuleV2.adaptToV1(capsule2)
        let capsule1Object = try jsonObject(JSONEncoder().encode(capsule1))
        var missingV1Risk = capsule1Object
        missingV1Risk.removeValue(forKey: "risk_level")
        XCTAssertThrowsError(try decodeCapsule1(missingV1Risk))

        var unknownV1 = capsule1Object
        unknownV1["unexpected_extension"] = true
        XCTAssertEqual(try decodeCapsule1(unknownV1), capsule1)

        var unknownV1Trace = capsule1Object
        var v1Trace = try XCTUnwrap(unknownV1Trace["trace"] as? [String: Any])
        v1Trace["future_runtime_observation"] = ["observed": false]
        unknownV1Trace["trace"] = v1Trace
        XCTAssertEqual(try decodeCapsule1(unknownV1Trace), capsule1)

        var unknownV1Signature = capsule1Object
        var v1Signature = try XCTUnwrap(unknownV1Signature["signature"] as? [String: Any])
        v1Signature["future_trust_claim"] = false
        unknownV1Signature["signature"] = v1Signature
        XCTAssertThrowsError(try decodeCapsule1(unknownV1Signature))

        var nullV1Extension = capsule1Object
        nullV1Extension["extends_chain"] = NSNull()
        XCTAssertEqual(try decodeCapsule1(nullV1Extension), capsule1)
        XCTAssertEqual(try decodeCapsule1(capsule1Object), capsule1)
    }

    func testCapsulePublicValueGraphIsSendable() {
        requireSendable(KDNACapsule2Error.self)
        requireSendable(KDNAExpectedDigest.self)
        requireSendable(KDNAExpectedDigests.self)
        requireSendable(KDNADigestComparison.self)
        requireSendable(KDNADigestObservation.self)
        requireSendable(KDNADigestEvidence.self)
        requireSendable(KDNAContextCapsuleSignature.self)
        requireSendable(KDNAContextCapsuleTrace.self)
        requireSendable(KDNAJSONValue.self)
        requireSendable(KDNAContextCapsule.self)
        requireSendable(KDNAContextCapsule2Asset.self)
        requireSendable(KDNAContextCapsule2Trace.self)
        requireSendable(KDNAContextCapsule1Extensions.self)
        requireSendable(KDNAContextCapsule2Compatibility.self)
        requireSendable(KDNAContextCapsule2.self)
    }

    private func goldenBytes() throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/capsule-v2-minimal.kdna.b64")
        let encoded = try String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return try XCTUnwrap(Data(base64Encoded: encoded))
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func assetBytes(access: String) throws -> Data {
        let bytes = try goldenBytes()
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: bytes)
        let payload = try reader.readEntry(asset: asset, name: "payload.kdnab")
        let mimetype = try reader.readEntry(asset: asset, name: "mimetype")
        var manifest = try XCTUnwrap(reader.readManifest(asset: asset))
        manifest["access"] = access
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let entrySetDigest = KDNAChecksumDigests.computeRuntimeEntrySetDigest(
            manifest: manifestData,
            payload: payload
        )
        let checksums = try JSONSerialization.data(withJSONObject: [
            "algorithm": "sha256",
            "digest_profile": "kdna-runtime-entry-set-v1",
            "covered_entries": ["kdna.json", "payload.kdnab"],
            "manifest_digest": "sha256:\(sha256Hex(manifestData))",
            "payload_digest": "sha256:\(sha256Hex(payload))",
            "entry_set_digest": entrySetDigest,
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        return makeZip(entries: [
            ("mimetype", mimetype),
            ("checksums.json", checksums),
            ("kdna.json", manifestData),
            ("payload.kdnab", payload),
        ])
    }

    private func capsule1ReplacingAccess(
        _ capsule: KDNAContextCapsule,
        access: String,
        assetDigest: String? = nil
    ) -> KDNAContextCapsule {
        KDNAContextCapsule(
            type: capsule.type,
            version: capsule.version,
            domain: capsule.domain,
            judgment_version: capsule.judgment_version,
            asset_digest: assetDigest ?? capsule.asset_digest,
            signature: capsule.signature,
            access: access,
            risk_level: capsule.risk_level,
            profile: capsule.profile,
            context: capsule.context,
            trace: capsule.trace,
            extends_chain: capsule.extends_chain,
            inheritance_applied: capsule.inheritance_applied,
            resolved_dependencies: capsule.resolved_dependencies,
            rag_isolation_policy: capsule.rag_isolation_policy
        )
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decodeCapsule2(_ object: [String: Any]) throws -> KDNAContextCapsule2 {
        try JSONDecoder().decode(
            KDNAContextCapsule2.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }

    private func decodeCapsule1(_ object: [String: Any]) throws -> KDNAContextCapsule {
        try JSONDecoder().decode(
            KDNAContextCapsule.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }

    private func requireSendable<T: Sendable>(_: T.Type) {}

    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = [Data]()
        var centralParts = [Data]()
        var offset: UInt32 = 0

        func u16(_ number: UInt16) -> Data {
            var value = number
            return Data(bytes: &value, count: 2)
        }
        func u32(_ number: UInt32) -> Data {
            var value = number
            return Data(bytes: &value, count: 4)
        }

        for (name, data) in entries {
            let nameData = Data(name.utf8)
            var local = Data()
            local.append(u32(0x04034b50))
            local.append(u16(20)); local.append(u16(0)); local.append(u16(0))
            local.append(u16(0)); local.append(u16(0)); local.append(u32(0))
            local.append(u32(UInt32(data.count))); local.append(u32(UInt32(data.count)))
            local.append(u16(UInt16(nameData.count))); local.append(u16(0))
            local.append(nameData); local.append(data)
            localParts.append(local)

            var central = Data()
            central.append(u32(0x02014b50))
            central.append(u16(20)); central.append(u16(20)); central.append(u16(0))
            central.append(u16(0)); central.append(u16(0)); central.append(u16(0))
            central.append(u32(0)); central.append(u32(UInt32(data.count)))
            central.append(u32(UInt32(data.count))); central.append(u16(UInt16(nameData.count)))
            central.append(u16(0)); central.append(u16(0)); central.append(u16(0))
            central.append(u16(0)); central.append(u32(0)); central.append(u32(offset))
            central.append(nameData)
            centralParts.append(central)
            offset += UInt32(local.count)
        }

        let local = localParts.reduce(Data(), +)
        let central = centralParts.reduce(Data(), +)
        var eocd = Data()
        eocd.append(u32(0x06054b50)); eocd.append(u16(0)); eocd.append(u16(0))
        eocd.append(u16(UInt16(entries.count))); eocd.append(u16(UInt16(entries.count)))
        eocd.append(u32(UInt32(central.count))); eocd.append(u32(UInt32(local.count)))
        eocd.append(u16(0))
        return local + central + eocd
    }
}
