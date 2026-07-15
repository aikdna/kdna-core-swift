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
