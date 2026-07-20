import XCTest
import CryptoKit
@testable import KDNACore

final class SchemaValidationTests: XCTestCase {
    func testBlockedCapsuleNegotiationIssueCodeMatchesRuntimeAuthority() throws {
        let data = try KDNACanonicalSchemas.resourceData(named: "judgment-trace.schema.json")
        let schema = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        let definitions = try XCTUnwrap(schema["$defs"] as? [String: Any])
        let runtimeContract = try XCTUnwrap(definitions["runtimeContract"] as? [String: Any])
        let properties = try XCTUnwrap(runtimeContract["properties"] as? [String: Any])
        let issueCode = try XCTUnwrap(properties["issue_code"] as? [String: Any])
        let values = try XCTUnwrap(issueCode["enum"] as? [Any])
        let codes = Set(values.compactMap { $0 as? String })

        XCTAssertTrue(codes.contains("KDNA_CAPSULE_CONTRACT_VERSION_UNSUPPORTED"))
    }

    func testBundledCanonicalSchemasHonorDigestLocksAndPinnedNodeParity() throws {
        XCTAssertEqual(
            KDNACanonicalSchemas.canonicalCommit,
            "f13390916c0b6a71aed8a62c458b5c440985ad98"
        )
        let expectedNames = Set([
            "agent-host-capabilities.schema.json",
            "agent-host-receipt.schema.json",
            "agent-host-request.schema.json",
            "bundle-profile.schema.json",
            "checksums.schema.json",
            "consumption-plan.schema.json",
            "digest-evidence.schema.json",
            "external-grant-envelope.schema.json",
            "external-key-grant.schema.json",
            "judgment-trace.schema.json",
            "load-contract.schema.json",
            "load-plan.schema.json",
            "manifest.schema.json",
            "payload-profile.schema.json",
            "runtime-capsule.schema.json",
        ])
        XCTAssertEqual(Set(KDNACanonicalSchemas.expectedDigests.keys), expectedNames)

        for name in expectedNames.sorted() {
            _ = try KDNACanonicalSchemas.resourceData(named: name)
        }

        // A standalone SwiftPM checkout has no sibling Node repository. CI
        // always sets this variable after checking out the pinned commit, so
        // the authoritative cross-repository byte comparison remains required
        // there while local package tests still verify every embedded SHA lock.
        guard let conformanceRoot = ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"],
              !conformanceRoot.isEmpty else { return }
        let nodeRepositoryRoot = URL(
            fileURLWithPath: conformanceRoot,
            isDirectory: true
        ).standardizedFileURL
        let nodeRootValues = try nodeRepositoryRoot.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )
        XCTAssertEqual(nodeRootValues.isDirectory, true)
        XCTAssertEqual(nodeRootValues.isSymbolicLink, false)
        XCTAssertEqual(
            nodeRepositoryRoot.path,
            nodeRepositoryRoot.resolvingSymlinksInPath().standardizedFileURL.path,
            "KDNA_CONFORMANCE_ROOT must be a direct Node repository checkout, not a symlink."
        )
        let coreSchemaRoot = nodeRepositoryRoot
            .appendingPathComponent("packages", isDirectory: true)
            .appendingPathComponent("kdna-core", isDirectory: true)
            .appendingPathComponent("schema", isDirectory: true)
        let canonicalNames = try FileManager.default.contentsOfDirectory(
            at: coreSchemaRoot,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "json" }.map(\.lastPathComponent)
        XCTAssertEqual(Set(canonicalNames), expectedNames)

        for name in expectedNames.sorted() {
            let canonicalURL = coreSchemaRoot.appendingPathComponent(name, isDirectory: false)
            let values = try canonicalURL.resourceValues(
                forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
            )
            XCTAssertEqual(values.isRegularFile, true)
            XCTAssertEqual(values.isSymbolicLink, false)
            XCTAssertEqual(
                try KDNACanonicalSchemas.resourceData(named: name),
                try Data(contentsOf: canonicalURL),
                "Bundled \(name) drifted from canonical Node schema."
            )
        }
    }

    func testAJVGeneratedFormatBoundariesMatchSwift() throws {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "schema-format-ajv",
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
            "format_version", "asset_id", "asset_uid", "asset_type", "title",
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

        for field in ["signature", "signatures"] {
            var legacySignature = manifest
            legacySignature[field] = field == "signature"
                ? "ed25519:legacy"
                : ["signatures/legacy.json"]
            XCTAssertFalse(
                KDNACanonicalSchemas.validateManifest(legacySignature).isEmpty,
                "Legacy asset-signature field was accepted: \(field)"
            )
        }

        for profile in ["password", "local_receipt", "account", "org"] {
            var licensed = manifest
            licensed["access"] = "licensed"
            licensed["entitlement"] = [
                "profile": profile,
                "offline": profile != "account",
                "revocable": profile != "password",
            ] as [String: Any]
            XCTAssertTrue(
                KDNACanonicalSchemas.validateManifest(licensed).isEmpty,
                "Supported entitlement profile was rejected: \(profile)"
            )
        }

        var licensedWithoutEntitlement = manifest
        licensedWithoutEntitlement["access"] = "licensed"
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(licensedWithoutEntitlement).isEmpty)

        var unknownEntitlement = manifest
        unknownEntitlement["access"] = "licensed"
        unknownEntitlement["entitlement"] = ["profile": "coupon_code"]
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(unknownEntitlement).isEmpty)

        var publicWithEntitlement = manifest
        publicWithEntitlement["entitlement"] = ["profile": "password"]
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(publicWithEntitlement).isEmpty)
    }

    func testManifestSchemaBindsEncryptedPayloadDeclarationExactly() {
        var encrypted = validManifest()
        encrypted["payload"] = [
            "path": "payload.kdnab",
            "encoding": "cbor",
            "encrypted": true,
        ]
        encrypted["encryption"] = [
            "profile": "kdna.encryption.password",
            "profile_version": "0.1.0",
            "encrypted_entries": ["payload.kdnab"],
        ]
        XCTAssertTrue(KDNACanonicalSchemas.validateManifest(encrypted).isEmpty)

        var missing = encrypted
        missing.removeValue(forKey: "encryption")
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(missing).isEmpty)

        var missingVersion = encrypted
        var encryption = missingVersion["encryption"] as! [String: Any]
        encryption.removeValue(forKey: "profile_version")
        missingVersion["encryption"] = encryption
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(missingVersion).isEmpty)

        var wrongVersion = encrypted
        encryption = wrongVersion["encryption"] as! [String: Any]
        encryption["profile_version"] = "9.9.9"
        wrongVersion["encryption"] = encryption
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(wrongVersion).isEmpty)

        for entries in [
            ["other.bin"] as Any,
            ["payload.kdnab", "other.bin"] as Any,
            ["entry": "payload.kdnab"] as Any,
            7 as Any,
        ] {
            var candidate = encrypted
            encryption = candidate["encryption"] as! [String: Any]
            encryption["encrypted_entries"] = entries
            candidate["encryption"] = encryption
            XCTAssertFalse(
                KDNACanonicalSchemas.validateManifest(candidate).isEmpty,
                "Malformed encrypted_entries was accepted: \(entries)"
            )
        }

        var falsePayloadFlag = encrypted
        var payload = falsePayloadFlag["payload"] as! [String: Any]
        payload["encrypted"] = false
        falsePayloadFlag["payload"] = payload
        XCTAssertFalse(KDNACanonicalSchemas.validateManifest(falsePayloadFlag).isEmpty)
    }

    func testPayloadSchemaEnforcesRequiredAndNestedShapes() {
        let payload = validPayload()
        XCTAssertTrue(KDNACanonicalSchemas.validatePayload(payload).isEmpty)

        for key in ["profile", "profile_version", "core"] {
            var candidate = payload
            candidate.removeValue(forKey: key)
            XCTAssertFalse(KDNACanonicalSchemas.validatePayload(candidate).isEmpty)
        }
        for key in ["axioms"] {
            var candidate = payload
            var core = candidate["core"] as! [String: Any]
            core.removeValue(forKey: key)
            candidate["core"] = core
            XCTAssertFalse(KDNACanonicalSchemas.validatePayload(candidate).isEmpty)
        }

        var withoutHighestQuestion = payload
        var scopedCore = withoutHighestQuestion["core"] as! [String: Any]
        scopedCore.removeValue(forKey: "highest_question")
        withoutHighestQuestion["core"] = scopedCore
        XCTAssertTrue(KDNACanonicalSchemas.validatePayload(withoutHighestQuestion).isEmpty)

        var emptyShell = payload
        var emptyCore = emptyShell["core"] as! [String: Any]
        emptyCore["highest_question"] = "   "
        emptyCore["axioms"] = [] as [Any]
        emptyShell["core"] = emptyCore
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(emptyShell).isEmpty)

        var fakeBoundary = payload
        var fakeBoundaryCore = fakeBoundary["core"] as! [String: Any]
        fakeBoundaryCore.removeValue(forKey: "highest_question")
        fakeBoundaryCore["boundaries"] = [["internal_note": NSNull()]]
        fakeBoundary["core"] = fakeBoundaryCore
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(fakeBoundary).isEmpty)

        var whitespaceApplicability = payload
        var whitespaceCore = whitespaceApplicability["core"] as! [String: Any]
        whitespaceCore.removeValue(forKey: "highest_question")
        whitespaceCore["axioms"] = [[
            "statement": "Whitespace is not an applicability boundary.",
            "applies_when": ["   "],
        ]]
        whitespaceApplicability["core"] = whitespaceCore
        XCTAssertFalse(KDNACanonicalSchemas.validatePayload(whitespaceApplicability).isEmpty)

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

    func testPayloadSelfCheckUsesOnlyCanonicalSingularField() throws {
        let schema = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: KDNACanonicalSchemas.resourceData(named: "payload-profile.schema.json")
            ) as? [String: Any]
        )
        let properties = try XCTUnwrap(schema["properties"] as? [String: Any])
        let reasoning = try XCTUnwrap(properties["reasoning"] as? [String: Any])
        let reasoningProperties = try XCTUnwrap(reasoning["properties"] as? [String: Any])
        XCTAssertNotNil(reasoningProperties["self_check"])
        XCTAssertEqual(reasoningProperties["self_checks"] as? Bool, false)

        var stringAndObject = validPayload()
        stringAndObject["reasoning"] = [
            "self_check": [
                "Did I preserve the canonical question?",
                ["question": "Did I preserve the structured question?"],
            ] as [Any],
        ]
        XCTAssertTrue(KDNACanonicalSchemas.validatePayload(stringAndObject).isEmpty)

        for keepCanonicalField in [false, true] {
            var deprecatedAlias = validPayload()
            var deprecatedReasoning = deprecatedAlias["reasoning"] as! [String: Any]
            if !keepCanonicalField {
                deprecatedReasoning.removeValue(forKey: "self_check")
            }
            deprecatedReasoning["self_checks"] = ["This alias must never be accepted."]
            deprecatedAlias["reasoning"] = deprecatedReasoning

            let issues = KDNACanonicalSchemas.validatePayload(deprecatedAlias)
            XCTAssertTrue(issues.contains { $0.contains("$.reasoning.self_checks") })
        }
    }

    func testCanonicalNodeSelfCheckFixturePreservesCompactAndRenderedProjection() throws {
        guard let conformanceRoot = ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"],
              !conformanceRoot.isEmpty else { return }
        let fixtureURL = URL(fileURLWithPath: conformanceRoot)
            .appendingPathComponent("packages/kdna-core/test/fixtures/golden-single-asset.json")
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any]
        )
        let fixturePayload = try XCTUnwrap(fixture["payload"] as? [String: Any])
        let reasoning = try XCTUnwrap(fixturePayload["reasoning"] as? [String: Any])
        let selfCheck = try XCTUnwrap(reasoning["self_check"] as? [Any])
        let textQuestion = try XCTUnwrap(selfCheck.first as? String)
        let structured = try XCTUnwrap(selfCheck.dropFirst().first as? [String: Any])
        let structuredQuestion = try XCTUnwrap(structured["question"] as? String)
        XCTAssertTrue(KDNACanonicalSchemas.validatePayload(fixturePayload).isEmpty)

        let bytes = try mutatedGolden { _, payload in
            payload = fixturePayload
        }
        let capsule = try KDNARuntime.load(
            assetData: bytes,
            loadedAt: "2026-07-15T00:00:00.000Z"
        )
        let projected = try XCTUnwrap(capsule.context["self_checks"]?.arrayValue)
        XCTAssertEqual(capsule.context["self_checks"], KDNAJSONValue(any: selfCheck))
        XCTAssertEqual(projected.count, 2)
        XCTAssertEqual(projected[0].stringValue, textQuestion)
        XCTAssertEqual(projected[1]["question"]?.stringValue, structuredQuestion)

        let assetURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-self-check-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: assetURL) }
        try bytes.write(to: assetURL)
        let projection = try KDNARuntime.loadWithCredential(assetURL: assetURL)
        let section = try XCTUnwrap(projection.sections.first { $0.id == "self_checks" })
        XCTAssertEqual(section.items, [textQuestion, structuredQuestion])
        XCTAssertTrue(projection.prompt.contains(textQuestion))
        XCTAssertTrue(projection.prompt.contains(structuredQuestion))
    }

    func testCompactRuntimeProfilePreservesEveryDeclaredPattern() throws {
        let patterns = (1...5).map { ["type": "pattern", "text": "Pattern \($0)"] }
        let bytes = try mutatedGolden { _, payload in
            payload["patterns"] = patterns
        }
        let capsule = try KDNARuntime.load(
            assetData: bytes,
            loadedAt: "2026-07-15T00:00:00.000Z"
        )
        let projected = try XCTUnwrap(capsule.context["patterns"]?.arrayValue)
        XCTAssertEqual(projected.count, 5)
        XCTAssertEqual(capsule.context["patterns"], KDNAJSONValue(any: patterns))
    }

    func testCompactRuntimeProfileReportsOmittedPayloadPathsAndCounts() throws {
        let bytes = try mutatedGolden { _, payload in
            var core = payload["core"] as? [String: Any] ?? [:]
            core["axioms"] = [[
                "id": "axiom-1",
                "one_sentence": "Prefer the declared recovery path.",
                "full_statement": "Prefer the declared recovery path when rollback evidence is incomplete.",
                "why": "A reversible path limits harm.",
                "confidence": "high",
                "applies_when": ["rollback evidence is incomplete"],
                "does_not_apply_when": ["required checks failed"],
                "failure_risk": "Expansion may outrun recovery.",
            ]]
            core["ontology"] = [["id": "concept-1"], ["id": "concept-2"]]
            core["risk_model"] = ["risks": [["id": "risk-1"], ["id": "risk-2"]]]
            payload["core"] = core

            var reasoning = payload["reasoning"] as? [String: Any] ?? [:]
            reasoning["reasoning_chains"] = [["id": "chain-1"]]
            payload["reasoning"] = reasoning
            payload["scenarios"] = [["id": "scenario-1"], ["id": "scenario-2"]]
            payload["cases"] = [["id": "case-1"]]
            payload["evolution"] = [
                "changelog": [["version": "1.0.0"]],
                "version_notes": ["note one", "note two"],
            ]
        }
        let capsule = try KDNARuntime.load(
            assetData: bytes,
            loadedAt: "2026-07-15T00:00:00.000Z"
        )
        let report = try XCTUnwrap(capsule.trace.projection_report)
        XCTAssertEqual(report.status, "partial")
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: report.omitted.map { ($0.path, $0.count) }), [
            "/cases": 1,
            "/core/axioms/*/confidence": 1,
            "/core/axioms/*/full_statement": 1,
            "/core/axioms/*/why": 1,
            "/core/ontology": 2,
            "/core/risk_model/risks": 2,
            "/evolution/changelog": 1,
            "/evolution/version_notes": 2,
            "/reasoning/reasoning_chains": 1,
            "/scenarios": 2,
        ])
        XCTAssertEqual(report.omitted_total, 14)
    }

    func testCompactRuntimeProfileDoesNotTrimFullStatementFallback() throws {
        let fullStatement = "Keep every declared character " + String(repeating: "x", count: 180)
        let bytes = try mutatedGolden { _, payload in
            payload["core"] = [
                "highest_question": "What must remain exact?",
                "axioms": [[
                    "full_statement": fullStatement,
                    "applies_when": ["first condition", "second condition", "third condition"],
                    "does_not_apply_when": ["first exclusion", "second exclusion", "third exclusion"],
                ]],
            ]
            payload["patterns"] = []
            payload["reasoning"] = ["self_check": [], "failure_modes": []]
            payload["scenarios"] = []
            payload["cases"] = []
            payload["evolution"] = ["changelog": [], "version_notes": []]
        }
        let capsule = try KDNARuntime.load(
            assetData: bytes,
            loadedAt: "2026-07-15T00:00:00.000Z"
        )
        let axiom = try XCTUnwrap(capsule.context["axioms"]?.arrayValue?.first)
        XCTAssertEqual(axiom["one_sentence"]?.stringValue, fullStatement)
        XCTAssertEqual(axiom["applies_when"]?.arrayValue?.count, 3)
        XCTAssertEqual(axiom["does_not_apply_when"]?.arrayValue?.count, 3)
        XCTAssertEqual(capsule.trace.projection_report, KDNAProjectionReport(
            status: "partial",
            omitted: [KDNAProjectionOmission(path: "/core/axioms/*/full_statement", count: 1)],
            omitted_total: 1
        ))
    }

    func testLoadPlanAndRuntimeRejectDeprecatedPluralSelfChecks() throws {
        for keepCanonicalField in [false, true] {
            let bytes = try mutatedGolden { _, payload in
                var reasoning = payload["reasoning"] as? [String: Any] ?? [:]
                if keepCanonicalField {
                    reasoning["self_check"] = ["Canonical question remains present."]
                } else {
                    reasoning.removeValue(forKey: "self_check")
                }
                reasoning["self_checks"] = ["Deprecated plural question."]
                payload["reasoning"] = reasoning
            }
            let plan = KDNALoadPlanCore.planLoad(assetData: bytes)
            XCTAssertFalse(plan.checks.payload_valid)
            XCTAssertFalse(plan.checks.overall_valid)
            XCTAssertFalse(plan.can_load_now)
            XCTAssertTrue(plan.issues.contains { $0.message.contains("$.reasoning.self_checks") })
            XCTAssertThrowsError(try KDNARuntime.load(assetData: bytes)) { error in
                guard case KDNALoadError.notAuthorized(let rejectedPlan) = error else {
                    return XCTFail("expected fail-closed LoadPlan rejection, got \(error)")
                }
                XCTAssertFalse(rejectedPlan.can_load_now)
                XCTAssertTrue(
                    rejectedPlan.issues.contains { $0.message.contains("$.reasoning.self_checks") }
                )
            }
        }
    }

    func testLoadPlanAndCapsuleFailClosedOnFormalSchemaViolations() throws {
        let invalidManifestBytes = try mutatedGolden { manifest, _ in
            manifest["title"] = ""
        }
        let manifestPlan = KDNALoadPlanCore.planLoad(assetData: invalidManifestBytes)
        XCTAssertFalse(manifestPlan.checks.schema_valid)
        XCTAssertFalse(manifestPlan.can_load_now)
        XCTAssertThrowsError(try KDNARuntime.load(assetData: invalidManifestBytes))

        let invalidPayloadBytes = try mutatedGolden { _, payload in
            var core = payload["core"] as! [String: Any]
            core["worldview"] = [1]
            payload["core"] = core
        }
        let payloadPlan = KDNALoadPlanCore.planLoad(assetData: invalidPayloadBytes)
        XCTAssertFalse(payloadPlan.checks.payload_valid)
        XCTAssertFalse(payloadPlan.can_load_now)
        XCTAssertThrowsError(try KDNARuntime.load(assetData: invalidPayloadBytes))

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
        let validFEFFCapsule = try KDNARuntime.load(assetData: validFEFFDateBytes)
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
            profile: "kdna.digest-evidence",
            profile_version: "0.1.0",
            asset: KDNADigestObservation(
                value: nil,
                basis: "kdna.digest-basis.container-bytes",
                comparison: unavailable
            ),
            content: KDNADigestObservation(
                value: nil,
                basis: "kdna.digest-basis.content-tree",
                comparison: unavailable
            ),
            runtime_entry_set: KDNADigestObservation(
                value: nil,
                basis: "kdna.digest-basis.runtime-entry-set",
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
            "format_version": "0.1.0",
            "asset_id": "kdna:test:schema",
            "asset_uid": "urn:uuid:00190000-0000-4000-8000-000000000001",
            "asset_type": "fixture",
            "title": "Schema Fixture",
            "version": "1.0.0",
            "judgment_version": "1.0.0",
            "created_at": "2026-07-15T00:00:00Z",
            "updated_at": "2026-07-15T00:00:00Z",
            "compatibility": [
                "min_loader_version": "0.20.0",
                "profile": "kdna.payload.judgment",
                "profile_version": "0.1.0",
            ],
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
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0",
            "core": [
                "highest_question": "Does formal schema validation hold?",
                "worldview": ["Validation is evidence."],
                "axioms": [[
                    "statement": "Reject malformed assets before loading.",
                    "applies_when": ["validating a packaged KDNA asset"],
                ]] as [Any],
            ] as [String: Any],
            "reasoning": ["self_check": [["question": "Was every ref followed?"]]],
        ]
    }

    private func mutatedGolden(
        _ mutate: (inout [String: Any], inout [String: Any]) -> Void
    ) throws -> Data {
        var manifest = validManifest()
        var payload = validPayload()
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
            "digest_profile": "kdna.digest-basis.runtime-entry-set",
            "digest_profile_version": "0.1.0",
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
