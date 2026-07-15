import XCTest
@testable import KDNACore

final class RuntimeContractTests: XCTestCase {
    private let loadedAt = "2026-07-15T00:00:00.000Z"

    func testCurrentCapsuleMatchesNodeGoldenACEPAndWireShape() throws {
        let fixture = try golden()
        let expectedRequest = try object(fixture, "request")
        let expectedCapsule = try XCTUnwrap(expectedRequest["capsule"] as? [String: Any])
        let bytes = try packagedBytes()
        let capsule = try KDNARuntime.load(
            assetData: bytes,
            expected: KDNAExpectedDigests(asset: KDNAExpectedDigest(
                value: "sha256:df18a4b15c930940061c58744c0bcac040a0a54c596db358da02c0a31082a23e",
                source: "install_receipt"
            )),
            loadedAt: loadedAt
        )

        XCTAssertEqual(capsule.type, "kdna.runtime-capsule")
        XCTAssertEqual(capsule.contract_version, "0.1.0")
        XCTAssertEqual(capsule.digests.asset.value, "sha256:df18a4b15c930940061c58744c0bcac040a0a54c596db358da02c0a31082a23e")
        XCTAssertEqual(capsule.digests.content.value, "sha256:72595802e214dff1a5b5a1153dd7e343190668d5da5ba32bcff2857774cc9428")
        XCTAssertEqual(capsule.digests.runtime_entry_set.value, "sha256:52b8ceb0dfe2081dc955487de31bc693e14f3a51ed5a79ece7a4e1ac26249de7")
        XCTAssertEqual(
            try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule),
            "sha256:3ff3f7986c437460fc6a09de9d864d7d2d3d551571a3a95b2dac21b4a63ee4fa"
        )
        XCTAssertEqual(capsule.jsonValue, KDNAJSONValue(any: expectedCapsule))

        let encoded = try JSONEncoder().encode(capsule)
        XCTAssertEqual(try JSONDecoder().decode(KDNARuntimeCapsule.self, from: encoded), capsule)
    }

    func testCurrentCrossLanguageCoverageMatrixIsPinnedToNodeAuthority() throws {
        XCTAssertEqual(
            KDNACanonicalSchemas.canonicalCommit,
            "4ede2aa539b94edd45aac973a0b4937c734c544a"
        )

        let capsule = try KDNARuntime.load(
            assetData: packagedBytes(),
            expected: KDNAExpectedDigests(asset: KDNAExpectedDigest(
                value: "sha256:df18a4b15c930940061c58744c0bcac040a0a54c596db358da02c0a31082a23e",
                source: "install_receipt"
            )),
            loadedAt: loadedAt
        )
        XCTAssertEqual(
            capsule.digests.asset.value,
            "sha256:df18a4b15c930940061c58744c0bcac040a0a54c596db358da02c0a31082a23e",
            "A must retain exact packaged-byte parity."
        )
        XCTAssertEqual(
            capsule.digests.content.value,
            "sha256:72595802e214dff1a5b5a1153dd7e343190668d5da5ba32bcff2857774cc9428",
            "C must retain cross-language canonical content-tree parity."
        )
        XCTAssertEqual(
            capsule.digests.runtime_entry_set.value,
            "sha256:52b8ceb0dfe2081dc955487de31bc693e14f3a51ed5a79ece7a4e1ac26249de7",
            "E must retain canonical Runtime entry-set parity."
        )
        XCTAssertEqual(
            try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule),
            "sha256:3ff3f7986c437460fc6a09de9d864d7d2d3d551571a3a95b2dac21b4a63ee4fa",
            "P must retain cross-language RFC 8785/JCS parity."
        )

        let nodeRoot = try XCTUnwrap(
            ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"]
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertFalse(nodeRoot.isEmpty)
        let repository = URL(fileURLWithPath: nodeRoot, isDirectory: true).standardizedFileURL
        XCTAssertEqual(
            repository.path,
            repository.resolvingSymlinksInPath().standardizedFileURL.path,
            "Cross-language authority must be a direct checkout."
        )
        let licensedFixture = repository
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("test_licensed_entry.kdna", isDirectory: false)
        let fixtureBytes = try Data(contentsOf: licensedFixture)
        XCTAssertEqual(
            KDNACrypto.sha256Hex(fixtureBytes),
            "d785725fc2b53cad5c3627ddc91ae737ab58502224e64dca8896ac818c4e9790"
        )
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: fixtureBytes, path: licensedFixture.path)
        let manifest = try reader.decodeManifest(asset: asset)
        XCTAssertEqual(manifest.encryption?.profile, KDNA_LICENSED_ENTRY_PROFILE)
        XCTAssertEqual(manifest.encryption?.profile_version, KDNA_ENCRYPTION_PROFILE_VERSION)
        let plaintext = try KDNALicensedEntryDecryptor(
            licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
        ).decrypt(
            entryName: "payload.kdnab",
            envelopeData: reader.readEntry(asset: asset, name: "payload.kdnab"),
            manifest: manifest
        )
        let canonicalPayload = try Data(contentsOf: repository
            .appendingPathComponent("examples/minimal/payload.kdnab"))
        XCTAssertEqual(
            try KDNACBOR.decodeObject(plaintext) as NSDictionary,
            try KDNACBOR.decodeObject(canonicalPayload) as NSDictionary,
            "Current Node encrypted fixture must really decrypt to the canonical payload."
        )
    }

    func testCurrentPlanHostReceiptAndTraceMatchNodeGolden() throws {
        let fixture = try golden()
        let plan = try decode(KDNAConsumptionPlan.self, object(fixture, "plan"))
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let request = try decode(KDNAAgentHostRequest.self, object(fixture, "request"))
        let receipt = try decode(KDNAAgentHostReceipt.self, object(fixture, "receipt"))
        let trace = try decode(KDNAJudgmentTrace.self, object(fixture, "trace"))
        let trusted = plan.planDigest

        XCTAssertEqual(
            try KDNARuntimeContracts.computeConsumptionPlanDigest(plan),
            "sha256:c3229f99fc39c56131bf255744f98a207e4597acc5f794ed30693ced40c914f1"
        )
        try KDNARuntimeContracts.validateConsumptionPlan(plan, trustedPlanDigest: trusted)
        XCTAssertEqual(
            KDNARuntimeContracts.negotiateRuntimePair(
                plan: plan,
                trustedPlanDigest: trusted,
                capabilities: capabilities
            ),
            KDNARuntimeNegotiation(
                state: "selected",
                capsule_version: "0.1.0",
                host_protocol: "kdna.agent-host",
                issue_code: nil
            )
        )
        try KDNARuntimeContracts.validateAgentHostRequest(
            request,
            plan: plan,
            trustedPlanDigest: trusted,
            capabilities: capabilities
        )
        try KDNARuntimeContracts.validateAgentHostReceipt(receipt, request: request)
        XCTAssertEqual(
            try KDNARuntimeContracts.deriveBudgetEvidence(
                plan: plan,
                trustedPlanDigest: trusted,
                request: request,
                receipt: receipt
            ),
            trace.jsonValue["budget"]
        )
        try KDNARuntimeContracts.validateJudgmentTrace(
            trace,
            plan: plan,
            trustedPlanDigest: trusted,
            capabilities: capabilities,
            request: request,
            receipt: receipt
        )

        let capsule = try decode(KDNARuntimeCapsule.self, object(object(fixture, "request"), "capsule"))
        let rebuilt = try KDNARuntimeContracts.buildAgentHostRequest(
            requestID: request.requestID,
            capsule: capsule,
            plan: plan,
            trustedPlanDigest: trusted,
            capabilities: capabilities
        )
        XCTAssertEqual(rebuilt, request)
    }

    func testMaliciousCorrelationBudgetAndDeliveryEvidenceFailClosed() throws {
        let fixture = try golden()
        let plan = try decode(KDNAConsumptionPlan.self, object(fixture, "plan"))
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let requestObject = try object(fixture, "request")
        let request = try decode(KDNAAgentHostRequest.self, requestObject)
        let receiptObject = try object(fixture, "receipt")
        let receipt = try decode(KDNAAgentHostReceipt.self, receiptObject)
        let trusted = plan.planDigest

        var badPlan = try object(fixture, "plan")
        var badIntegrity = try XCTUnwrap(badPlan["integrity"] as? [String: Any])
        badIntegrity["plan_digest"] = "sha256:" + String(repeating: "0", count: 64)
        badPlan["integrity"] = badIntegrity
        let decodedBadPlan = try decode(KDNAConsumptionPlan.self, badPlan)
        XCTAssertThrowsCode("KDNA_PLAN_DIGEST_MISMATCH") {
            try KDNARuntimeContracts.validateConsumptionPlan(
                decodedBadPlan,
                trustedPlanDigest: decodedBadPlan.planDigest
            )
        }

        var badRequestObject = requestObject
        var runtime = try XCTUnwrap(badRequestObject["runtime_contract"] as? [String: Any])
        runtime["capsule_delivery_digest"] = "sha256:" + String(repeating: "0", count: 64)
        badRequestObject["runtime_contract"] = runtime
        let badRequest = try decode(KDNAAgentHostRequest.self, badRequestObject)
        XCTAssertThrowsCode("KDNA_CAPSULE_DELIVERY_DIGEST_MISMATCH") {
            try KDNARuntimeContracts.validateAgentHostRequest(
                badRequest,
                plan: plan,
                trustedPlanDigest: trusted,
                capabilities: capabilities
            )
        }

        var wrongAuthorityObject = requestObject
        var authority = try XCTUnwrap(wrongAuthorityObject["authority"] as? [String: Any])
        authority["asset_id"] = "kdna:example:different"
        wrongAuthorityObject["authority"] = authority
        let wrongAuthority = try decode(KDNAAgentHostRequest.self, wrongAuthorityObject)
        XCTAssertThrowsCode("KDNA_HOST_ASSET_ID_MISMATCH") {
            try KDNARuntimeContracts.validateAgentHostRequest(
                wrongAuthority,
                plan: plan,
                trustedPlanDigest: trusted,
                capabilities: capabilities
            )
        }

        var badReceiptObject = receiptObject
        var runtimeReceipt = try XCTUnwrap(badReceiptObject["runtime_receipt"] as? [String: Any])
        runtimeReceipt["echoed_capsule_delivery_digest"] = "sha256:" + String(repeating: "1", count: 64)
        badReceiptObject["runtime_receipt"] = runtimeReceipt
        let badReceipt = try decode(KDNAAgentHostReceipt.self, badReceiptObject)
        XCTAssertThrowsCode("KDNA_HOST_CAPSULE_DELIVERY_DIGEST_MISMATCH") {
            try KDNARuntimeContracts.validateAgentHostReceipt(badReceipt, request: request)
        }

        var badTraceObject = try object(fixture, "trace")
        var budget = try XCTUnwrap(badTraceObject["budget"] as? [String: Any])
        var actual = try XCTUnwrap(budget["actual"] as? [String: Any])
        actual["projection_chars"] = 1
        budget["actual"] = actual
        badTraceObject["budget"] = budget
        let badTrace = try decode(KDNAJudgmentTrace.self, badTraceObject)
        XCTAssertThrowsCode("KDNA_TRACE_BUDGET_MISMATCH") {
            try KDNARuntimeContracts.validateJudgmentTrace(
                badTrace,
                plan: plan,
                trustedPlanDigest: trusted,
                capabilities: capabilities,
                request: request,
                receipt: receipt
            )
        }
    }

    func testPreHostProjectionBudgetIsEnforced() throws {
        let fixture = try golden()
        let sourcePlan = try object(fixture, "plan")
        var budget = try XCTUnwrap(sourcePlan["budget"] as? [String: Any])
        budget["max_projection_chars"] = 1
        let plan = try KDNARuntimeContracts.buildConsumptionPlan(
            planID: sourcePlan["plan_id"] as! String,
            createdAt: sourcePlan["created_at"] as! String,
            task: KDNAJSONValue(any: sourcePlan["task"]!),
            assetRef: KDNAJSONValue(any: sourcePlan["asset_ref"]!),
            projectionProfile: "compact",
            budget: KDNAJSONValue(any: budget),
            tracePolicy: KDNAJSONValue(any: sourcePlan["trace_policy"]!),
            constraints: KDNAJSONValue(any: sourcePlan["constraints"]!)
        )
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let capsule = try decode(KDNARuntimeCapsule.self, object(object(fixture, "request"), "capsule"))
        XCTAssertThrowsCode("KDNA_HOST_BUDGET_LIMIT_EXCEEDED") {
            _ = try KDNARuntimeContracts.buildAgentHostRequest(
                requestID: "host_0123456789abcdef01234567",
                capsule: capsule,
                plan: plan,
                trustedPlanDigest: plan.planDigest,
                capabilities: capabilities
            )
        }
    }

    func testPlanAndRequestBudgetIntegerBoundariesFailClosed() throws {
        let fixture = try golden()
        let fields: [(name: String, minimum: Double)] = [
            ("max_projection_chars", 0),
            ("max_task_chars", 0),
            ("deadline_ms", 1),
            ("max_tokens", 0),
            ("max_model_calls", 0),
        ]

        for field in fields {
            try assertSafeIntegerBoundaries(
                label: "plan.budget.\(field.name)",
                base: object(fixture, "plan"),
                path: ["budget", field.name],
                minimum: field.minimum
            ) { object in
                _ = try self.decode(KDNAConsumptionPlan.self, object)
            }
            try assertSafeIntegerBoundaries(
                label: "request.budget.\(field.name)",
                base: object(fixture, "request"),
                path: ["budget", field.name],
                minimum: field.minimum
            ) { object in
                _ = try self.decode(KDNAAgentHostRequest.self, object)
            }
        }

        for field in ["max_tokens", "max_model_calls"] {
            let nullablePlan = try replacing(
                NSNull(),
                at: ["budget", field],
                in: object(fixture, "plan")
            )
            XCTAssertNoThrow(try decode(KDNAConsumptionPlan.self, nullablePlan))
            let nullableRequest = try replacing(
                NSNull(),
                at: ["budget", field],
                in: object(fixture, "request")
            )
            XCTAssertNoThrow(try decode(KDNAAgentHostRequest.self, nullableRequest))
        }
    }

    func testReceiptObservationIntegerBoundariesFailClosed() throws {
        let receipt = try object(try golden(), "receipt")
        var reportedReceipt = try replacing(
            "host_reported",
            at: ["runtime_receipt", "usage", "basis"],
            in: receipt
        )
        reportedReceipt = try replacing(
            0.0,
            at: ["runtime_receipt", "usage", "tokens_used"],
            in: reportedReceipt
        )
        reportedReceipt = try replacing(
            0.0,
            at: ["runtime_receipt", "usage", "model_calls"],
            in: reportedReceipt
        )
        let outcomeReceipt = try replacing(
            ["tokens_used": 0.0, "model_calls": 0.0],
            at: ["outcome", "usage"],
            in: receipt
        )
        let targets: [(base: [String: Any], path: [String])] = [
            (receipt, ["runtime_receipt", "usage", "elapsed_ms"]),
            (reportedReceipt, ["runtime_receipt", "usage", "tokens_used"]),
            (reportedReceipt, ["runtime_receipt", "usage", "model_calls"]),
            (outcomeReceipt, ["outcome", "usage", "tokens_used"]),
            (outcomeReceipt, ["outcome", "usage", "model_calls"]),
        ]

        for target in targets {
            try assertSafeIntegerBoundaries(
                label: "receipt.\(target.path.joined(separator: "."))",
                base: target.base,
                path: target.path,
                minimum: 0
            ) { object in
                _ = try self.decode(KDNAAgentHostReceipt.self, object)
            }
        }
    }

    func testTraceBudgetAndEmbeddedObservationIntegerBoundariesFailClosed() throws {
        let trace = try object(try golden(), "trace")
        let limitFields: [(name: String, minimum: Double)] = [
            ("max_projection_chars", 0),
            ("max_task_chars", 0),
            ("deadline_ms", 1),
            ("max_tokens", 0),
            ("max_model_calls", 0),
        ]
        for field in limitFields {
            try assertSafeIntegerBoundaries(
                label: "trace.budget.limits.\(field.name)",
                base: trace,
                path: ["budget", "limits", field.name],
                minimum: field.minimum
            ) { object in
                _ = try self.decode(KDNAJudgmentTrace.self, object)
            }
        }

        var reportedActualTrace = try replacing(
            "host_reported",
            at: ["budget", "actual", "usage_basis"],
            in: trace
        )
        reportedActualTrace = try replacing(
            0.0,
            at: ["budget", "actual", "tokens_used"],
            in: reportedActualTrace
        )
        reportedActualTrace = try replacing(
            0.0,
            at: ["budget", "actual", "model_calls"],
            in: reportedActualTrace
        )
        let actualTargets: [(base: [String: Any], field: String)] = [
            (trace, "projection_chars"),
            (trace, "task_chars"),
            (trace, "elapsed_ms"),
            (reportedActualTrace, "tokens_used"),
            (reportedActualTrace, "model_calls"),
        ]
        for target in actualTargets {
            try assertSafeIntegerBoundaries(
                label: "trace.budget.actual.\(target.field)",
                base: target.base,
                path: ["budget", "actual", target.field],
                minimum: 0
            ) { object in
                _ = try self.decode(KDNAJudgmentTrace.self, object)
            }
        }

        var reportedHostTrace = try replacing(
            "host_reported",
            at: ["host_receipt", "runtime_receipt", "usage", "basis"],
            in: trace
        )
        reportedHostTrace = try replacing(
            0.0,
            at: ["host_receipt", "runtime_receipt", "usage", "tokens_used"],
            in: reportedHostTrace
        )
        reportedHostTrace = try replacing(
            0.0,
            at: ["host_receipt", "runtime_receipt", "usage", "model_calls"],
            in: reportedHostTrace
        )
        let outcomeHostTrace = try replacing(
            ["tokens_used": 0.0, "model_calls": 0.0],
            at: ["host_receipt", "outcome", "usage"],
            in: trace
        )
        let receiptTargets: [(base: [String: Any], path: [String])] = [
            (trace, ["host_receipt", "runtime_receipt", "usage", "elapsed_ms"]),
            (reportedHostTrace, ["host_receipt", "runtime_receipt", "usage", "tokens_used"]),
            (reportedHostTrace, ["host_receipt", "runtime_receipt", "usage", "model_calls"]),
            (outcomeHostTrace, ["host_receipt", "outcome", "usage", "tokens_used"]),
            (outcomeHostTrace, ["host_receipt", "outcome", "usage", "model_calls"]),
        ]
        for target in receiptTargets {
            try assertSafeIntegerBoundaries(
                label: "trace.\(target.path.joined(separator: "."))",
                base: target.base,
                path: target.path,
                minimum: 0
            ) { object in
                _ = try self.decode(KDNAJudgmentTrace.self, object)
            }
        }
    }

    func testRequestProjectionContractMustExactlyMatchPlanAndCapsule() throws {
        let fixture = try golden()
        let plan = try decode(KDNAConsumptionPlan.self, object(fixture, "plan"))
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let source = try object(fixture, "request")

        var wrongRequestProfile = source
        var projection = try XCTUnwrap(wrongRequestProfile["projection_contract"] as? [String: Any])
        projection["profile"] = "full"
        wrongRequestProfile["projection_contract"] = projection
        let requestProfileDrift = try decode(KDNAAgentHostRequest.self, wrongRequestProfile)
        XCTAssertThrowsCode("KDNA_HOST_PROJECTION_CONTRACT_MISMATCH") {
            try KDNARuntimeContracts.validateAgentHostRequest(
                requestProfileDrift,
                plan: plan,
                trustedPlanDigest: plan.planDigest,
                capabilities: capabilities
            )
        }

        var wrongCapsuleProfile = source
        var capsule = try XCTUnwrap(wrongCapsuleProfile["capsule"] as? [String: Any])
        capsule["profile"] = "full"
        wrongCapsuleProfile["capsule"] = capsule
        let capsuleProfileDrift = try decode(KDNAAgentHostRequest.self, wrongCapsuleProfile)
        XCTAssertThrowsCode("KDNA_HOST_PROJECTION_CONTRACT_MISMATCH") {
            try KDNARuntimeContracts.validateAgentHostRequest(
                capsuleProfileDrift,
                plan: plan,
                trustedPlanDigest: plan.planDigest,
                capabilities: capabilities
            )
        }
    }

    func testTraceRuntimeAuthorityRejectsCapabilityProfileAndVersionDrift() throws {
        let fixture = try golden()
        let plan = try decode(KDNAConsumptionPlan.self, object(fixture, "plan"))
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let request = try decode(KDNAAgentHostRequest.self, object(fixture, "request"))
        let receipt = try decode(KDNAAgentHostReceipt.self, object(fixture, "receipt"))
        let source = try object(fixture, "trace")

        for mutation in ["basis", "profile"] {
            var traceObject = source
            var runtime = try XCTUnwrap(traceObject["runtime_contract"] as? [String: Any])
            var embeddedCapabilities = try XCTUnwrap(runtime["host_capabilities"] as? [String: Any])
            if mutation == "basis" {
                embeddedCapabilities["capability_basis"] = "legacy_assumption"
            } else {
                embeddedCapabilities["capsule_digest_profiles"] = []
            }
            runtime["host_capabilities"] = embeddedCapabilities
            traceObject["runtime_contract"] = runtime
            let driftedTrace = try decode(KDNAJudgmentTrace.self, traceObject)
            XCTAssertThrowsCode("KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH") {
                try KDNARuntimeContracts.validateJudgmentTrace(
                    driftedTrace,
                    plan: plan,
                    trustedPlanDigest: plan.planDigest,
                    capabilities: capabilities,
                    request: request,
                    receipt: receipt
                )
            }
        }

        let trace = try decode(KDNAJudgmentTrace.self, source)
        XCTAssertThrowsCode("KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH") {
            try KDNARuntimeContracts.validateJudgmentTrace(
                trace,
                plan: plan,
                trustedPlanDigest: plan.planDigest,
                capabilities: capabilities,
                coreCapsuleVersions: [],
                request: request,
                receipt: receipt
            )
        }
    }

    func testAllCurrentTraceTerminalStatesValidateAgainstIndependentEvidence() throws {
        let fixture = try golden()
        let plan = try decode(KDNAConsumptionPlan.self, object(fixture, "plan"))
        let capabilities = try decode(KDNAAgentHostCapabilities.self, object(fixture, "capabilities"))
        let request = try decode(KDNAAgentHostRequest.self, object(fixture, "request"))

        for name in ["runtime-trace-execution-failed", "runtime-trace-cancelled", "runtime-trace-timed-out"] {
            let traceObject = try fixtureObject(name)
            let trace = try decode(KDNAJudgmentTrace.self, traceObject)
            let receipt = try decode(KDNAAgentHostReceipt.self, object(traceObject, "host_receipt"))
            try KDNARuntimeContracts.validateJudgmentTrace(
                trace,
                plan: plan,
                trustedPlanDigest: plan.planDigest,
                capabilities: capabilities,
                request: request,
                receipt: receipt
            )
        }

        let blocked = try decode(
            KDNAJudgmentTrace.self,
            fixtureObject("runtime-trace-blocked")
        )
        try KDNARuntimeContracts.validateBlockedJudgmentTrace(
            blocked,
            plan: plan,
            trustedPlanDigest: plan.planDigest,
            capabilities: capabilities
        )
    }

    private func golden() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "runtime-contract-golden",
            withExtension: "json"
        ))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func packagedBytes() throws -> Data {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "runtime-capsule-minimal.kdna",
            withExtension: "b64"
        ))
        let encoded = try String(contentsOf: url).trimmingCharacters(in: .whitespacesAndNewlines)
        return try XCTUnwrap(Data(base64Encoded: encoded))
    }

    private func fixtureObject(_ name: String) throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func object(_ object: [String: Any], _ key: String) throws -> [String: Any] {
        try XCTUnwrap(object[key] as? [String: Any])
    }

    private func decode<T: Decodable>(_ type: T.Type, _ object: [String: Any]) throws -> T {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return try JSONDecoder().decode(type, from: data)
    }

    private func replacing(
        _ value: Any,
        at path: [String],
        in object: [String: Any]
    ) throws -> [String: Any] {
        let key = try XCTUnwrap(path.first)
        var result = object
        if path.count == 1 {
            result[key] = value
            return result
        }
        let child = try XCTUnwrap(result[key] as? [String: Any])
        result[key] = try replacing(value, at: Array(path.dropFirst()), in: child)
        return result
    }

    private func assertSafeIntegerBoundaries(
        label: String,
        base: [String: Any],
        path: [String],
        minimum: Double,
        decode: ([String: Any]) throws -> Void
    ) throws {
        let maximumExactJSONInteger = 9_007_199_254_740_991.0
        for accepted in [minimum, maximumExactJSONInteger] {
            let candidate = try replacing(accepted, at: path, in: base)
            XCTAssertNoThrow(try decode(candidate), "\(label) should accept \(accepted)")
        }

        let belowMinimum = try replacing(minimum - 1, at: path, in: base)
        XCTAssertThrowsCode("SCHEMA_INVALID") {
            try decode(belowMinimum)
        }
        let fractional = try replacing(minimum + 0.5, at: path, in: base)
        XCTAssertThrowsCode("SCHEMA_INVALID") {
            try decode(fractional)
        }
        let precisionBoundary = try replacing(
            maximumExactJSONInteger + 1,
            at: path,
            in: base
        )
        XCTAssertThrowsCode("KDNA_RUNTIME_INTEGER_UNSAFE") {
            try decode(precisionBoundary)
        }
        let beyondSwiftInt = try replacing(1.0e20, at: path, in: base)
        XCTAssertThrowsCode("KDNA_RUNTIME_INTEGER_UNSAFE") {
            try decode(beyondSwiftInt)
        }
    }

    private func XCTAssertThrowsCode(
        _ code: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? KDNARuntimeContractError)?.code, code, file: file, line: line)
        }
    }
}
