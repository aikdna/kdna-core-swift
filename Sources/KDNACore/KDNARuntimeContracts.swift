import Foundation

public struct KDNARuntimeNegotiation: Codable, Equatable, Sendable {
    public let state: String
    public let capsule_version: String?
    public let host_protocol: String?
    public let issue_code: String?
}

public struct KDNAConsumptionPlan: Codable, Equatable, Sendable {
    public let jsonValue: KDNAJSONValue

    public init(jsonValue: KDNAJSONValue) throws {
        try KDNARuntimeContracts.requireSchema(jsonValue, kind: .plan)
        self.jsonValue = jsonValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(jsonValue: KDNAJSONValue(from: decoder))
    }

    public func encode(to encoder: Encoder) throws { try jsonValue.encode(to: encoder) }
    public var planID: String { jsonValue["plan_id"]?.stringValue ?? "" }
    public var planDigest: String { jsonValue["integrity"]?["plan_digest"]?.stringValue ?? "" }
}

public struct KDNAAgentHostCapabilities: Codable, Equatable, Sendable {
    public let jsonValue: KDNAJSONValue

    public init(jsonValue: KDNAJSONValue) throws {
        try KDNARuntimeContracts.requireSchema(jsonValue, kind: .capabilities)
        self.jsonValue = jsonValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(jsonValue: KDNAJSONValue(from: decoder))
    }

    public func encode(to encoder: Encoder) throws { try jsonValue.encode(to: encoder) }
}

public struct KDNAAgentHostRequest: Codable, Equatable, Sendable {
    public let jsonValue: KDNAJSONValue

    public init(jsonValue: KDNAJSONValue) throws {
        try KDNARuntimeContracts.requireSchema(jsonValue, kind: .request)
        self.jsonValue = jsonValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(jsonValue: KDNAJSONValue(from: decoder))
    }

    public func encode(to encoder: Encoder) throws { try jsonValue.encode(to: encoder) }
    public var requestID: String { jsonValue["request_id"]?.stringValue ?? "" }
}

public struct KDNAAgentHostReceipt: Codable, Equatable, Sendable {
    public let jsonValue: KDNAJSONValue

    public init(jsonValue: KDNAJSONValue) throws {
        try KDNARuntimeContracts.requireSchema(jsonValue, kind: .receipt)
        self.jsonValue = jsonValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(jsonValue: KDNAJSONValue(from: decoder))
    }

    public func encode(to encoder: Encoder) throws { try jsonValue.encode(to: encoder) }
}

public struct KDNAJudgmentTrace: Codable, Equatable, Sendable {
    public let jsonValue: KDNAJSONValue

    public init(jsonValue: KDNAJSONValue) throws {
        try KDNARuntimeContracts.requireSchema(jsonValue, kind: .trace)
        self.jsonValue = jsonValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(jsonValue: KDNAJSONValue(from: decoder))
    }

    public func encode(to encoder: Encoder) throws { try jsonValue.encode(to: encoder) }
    public var traceID: String { jsonValue["trace_id"]?.stringValue ?? "" }
}

public enum KDNARuntimeContracts {
    public static let contractVersion = "0.1.0"
    public static let planDigestProfile = "kdna.canonicalization.consumption-plan-jcs"
    public static let planDigestProfileVersion = "0.1.0"
    public static let hostProtocol = "kdna.agent-host"
    public static let hostProtocolVersion = "0.1.0"
    public static let coreCapsuleVersions = ["0.1.0"]

    enum SchemaKind { case plan, capabilities, request, receipt, trace }

    static func requireSchema(_ value: KDNAJSONValue, kind: SchemaKind) throws {
        let issues: [String]
        switch kind {
        case .plan: issues = KDNACanonicalSchemas.validateConsumptionPlan(value.anyValue)
        case .capabilities: issues = KDNACanonicalSchemas.validateAgentHostCapabilities(value.anyValue)
        case .request: issues = KDNACanonicalSchemas.validateAgentHostRequest(value.anyValue)
        case .receipt: issues = KDNACanonicalSchemas.validateAgentHostReceipt(value.anyValue)
        case .trace: issues = KDNACanonicalSchemas.validateJudgmentTrace(value.anyValue)
        }
        guard issues.isEmpty else {
            throw protocolError("SCHEMA_INVALID", "Runtime contract schema invalid: \(issues.joined(separator: "; "))")
        }
        try requireSafeRuntimeIntegers(value, kind: kind)
    }

    public static func computeConsumptionPlanDigest(_ plan: KDNAConsumptionPlan) throws -> String {
        try computePlanDigest(plan.jsonValue)
    }

    public static func validateConsumptionPlan(
        _ plan: KDNAConsumptionPlan,
        trustedPlanDigest: String
    ) throws {
        guard validDigest(trustedPlanDigest) else {
            throw protocolError(
                "KDNA_VALIDATION_CONTEXT_INVALID",
                "trustedPlanDigest must be a non-null lowercase sha256 digest."
            )
        }
        let computed = try computeConsumptionPlanDigest(plan)
        guard computed == plan.planDigest else {
            throw protocolError("KDNA_PLAN_DIGEST_MISMATCH", "ConsumptionPlan integrity correlation failed.")
        }
        guard computed == trustedPlanDigest else {
            throw protocolError(
                "KDNA_TRUSTED_PLAN_DIGEST_MISMATCH",
                "ConsumptionPlan does not match the independently trusted digest."
            )
        }
    }

    public static func buildConsumptionPlan(
        planID: String,
        createdAt: String,
        task: KDNAJSONValue,
        assetRef: KDNAJSONValue,
        projectionProfile: String,
        budget: KDNAJSONValue,
        tracePolicy: KDNAJSONValue,
        constraints: KDNAJSONValue
    ) throws -> KDNAConsumptionPlan {
        var object: [String: KDNAJSONValue] = [
            "type": .string("kdna.consumption-plan"),
            "contract_version": .string(contractVersion),
            "plan_id": .string(planID),
            "created_at": .string(createdAt),
            "mode": .string("single"),
            "task": task,
            "asset_ref": assetRef,
            "projection_request": .object([
                "profile": .string(projectionProfile),
                "accepted_capsule_versions": .array([.string(contractVersion)]),
                "required_digest_profile": .string(KDNARuntimeCapsuleCore.digestProfile),
                "required_digest_profile_version": .string(KDNARuntimeCapsuleCore.digestProfileVersion),
                "require_packaged_asset": .bool(true),
            ]),
            "host_request": .object(["accepted_protocols": .array([.string(hostProtocol)])]),
            "result_request": .object(["shape": .string("structured_judgment")]),
            "budget": budget,
            "trace_policy": tracePolicy,
            "integrity": .object([
                "profile": .string(planDigestProfile),
                "profile_version": .string(planDigestProfileVersion),
                "plan_digest": .string("sha256:" + String(repeating: "0", count: 64)),
            ]),
            "constraints": constraints,
        ]
        let digest = try computePlanDigest(.object(object))
        object["integrity"] = .object([
            "profile": .string(planDigestProfile),
            "profile_version": .string(planDigestProfileVersion),
            "plan_digest": .string(digest),
        ])
        let plan = try KDNAConsumptionPlan(jsonValue: .object(object))
        try validateConsumptionPlan(plan, trustedPlanDigest: digest)
        return plan
    }

    public static func negotiateRuntimePair(
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String] = coreCapsuleVersions
    ) -> KDNARuntimeNegotiation {
        do { try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest) }
        catch let error as KDNARuntimeContractError { return blocked(error.code) }
        catch { return blocked("KDNA_INPUT_INVALID") }

        let acceptedCapsules = strings(plan.jsonValue["projection_request"]?["accepted_capsule_versions"])
        let hostCapsules = strings(capabilities.jsonValue["capsule_versions"])
        guard acceptedCapsules.contains(contractVersion),
              coreCapsuleVersions.contains(contractVersion),
              hostCapsules.contains(contractVersion) else {
            return blocked("KDNA_CAPSULE_CONTRACT_VERSION_UNSUPPORTED")
        }
        let acceptedProtocols = strings(plan.jsonValue["host_request"]?["accepted_protocols"])
        let hostProtocols = strings(capabilities.jsonValue["host_protocols"])
        guard acceptedProtocols.contains(hostProtocol), hostProtocols.contains(hostProtocol) else {
            return blocked("KDNA_HOST_PROTOCOL_UNSUPPORTED")
        }
        guard capabilities.jsonValue["capability_basis"]?.stringValue == "registered_descriptor",
              strings(capabilities.jsonValue["capsule_digest_profiles"])
                .contains(KDNARuntimeCapsuleCore.deliveryDigestProfile),
              strings(capabilities.jsonValue["capsule_digest_profile_versions"])
                .contains(KDNARuntimeCapsuleCore.deliveryDigestProfileVersion) else {
            return blocked("KDNA_HOST_CAPSULE_PAIR_UNSUPPORTED")
        }
        return KDNARuntimeNegotiation(
            state: "selected",
            capsule_version: contractVersion,
            host_protocol: hostProtocol,
            issue_code: nil
        )
    }

    public static func buildAgentHostRequest(
        requestID: String,
        capsule: KDNARuntimeCapsule,
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String] = coreCapsuleVersions
    ) throws -> KDNAAgentHostRequest {
        try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest)
        let negotiation = negotiateRuntimePair(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        guard negotiation.state == "selected" else {
            throw protocolError(negotiation.issue_code ?? "KDNA_HOST_PAIR_UNSUPPORTED", "No strict Host pair selected.")
        }
        guard let planObject = plan.jsonValue.objectValue,
              let assetRef = planObject["asset_ref"]?.objectValue,
              let assetID = assetRef["asset_id"]?.stringValue,
              let projectionRequest = planObject["projection_request"]?.objectValue,
              let integrity = planObject["integrity"]?.objectValue else {
            throw protocolError("KDNA_HOST_REQUEST_INPUT_INVALID", "ConsumptionPlan fields are unavailable.")
        }
        var requestAsset = assetRef
        requestAsset["role"] = .string("primary")
        let value: KDNAJSONValue = .object([
            "protocol": .string(hostProtocol),
            "protocol_version": .string(hostProtocolVersion),
            "request_id": .string(requestID),
            "plan_ref": .object([
                "plan_id": planObject["plan_id"]!,
                "plan_digest_profile": integrity["profile"]!,
                "plan_digest_profile_version": integrity["profile_version"]!,
                "plan_digest": integrity["plan_digest"]!,
            ]),
            "runtime_contract": .object([
                "capsule_version": .string(contractVersion),
                "capsule_digest_profile": .string(KDNARuntimeCapsuleCore.deliveryDigestProfile),
                "capsule_digest_profile_version": .string(KDNARuntimeCapsuleCore.deliveryDigestProfileVersion),
                "capsule_delivery_digest": .string(try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule)),
            ]),
            "projection_contract": .object([
                "profile": projectionRequest["profile"]!,
                "required_digest_profile": projectionRequest["required_digest_profile"]!,
                "required_digest_profile_version": projectionRequest["required_digest_profile_version"]!,
                "require_packaged_asset": projectionRequest["require_packaged_asset"]!,
            ]),
            "result_contract": planObject["result_request"]!,
            "budget": planObject["budget"]!,
            "constraints": planObject["constraints"]!,
            "phase": .string("single_judgment"),
            "task": planObject["task"]!,
            "authority": .object([
                "asset_id": .string(assetID),
                "role": .string("primary"),
                "final_decision": .bool(true),
            ]),
            "asset": .object(requestAsset),
            "capsule": capsule.jsonValue,
        ])
        let request = try KDNAAgentHostRequest(jsonValue: value)
        try validateAgentHostRequest(
            request,
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        return request
    }

    public static func validateAgentHostRequest(
        _ request: KDNAAgentHostRequest,
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String] = coreCapsuleVersions,
        enforceBudget: Bool = true
    ) throws {
        try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest)
        let negotiation = negotiateRuntimePair(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        guard negotiation.state == "selected" else {
            throw protocolError(negotiation.issue_code ?? "KDNA_HOST_PAIR_UNSUPPORTED", "No strict Host pair selected.")
        }
        let requestValue = request.jsonValue
        let planValue = plan.jsonValue
        guard requestValue["plan_ref"]?["plan_id"] == planValue["plan_id"],
              requestValue["plan_ref"]?["plan_digest_profile"] == planValue["integrity"]?["profile"],
              requestValue["plan_ref"]?["plan_digest_profile_version"] == planValue["integrity"]?["profile_version"],
              requestValue["plan_ref"]?["plan_digest"] == planValue["integrity"]?["plan_digest"] else {
            throw protocolError("KDNA_HOST_PLAN_REF_MISMATCH", "Host request plan correlation failed.")
        }
        guard requestValue["task"] == planValue["task"] else {
            throw protocolError("KDNA_HOST_TASK_MISMATCH", "Host request task differs from the plan.")
        }
        guard requestValue["authority"]?["asset_id"] == planValue["asset_ref"]?["asset_id"] else {
            throw protocolError("KDNA_HOST_ASSET_ID_MISMATCH", "Host authority asset differs from the plan.")
        }
        var expectedAsset = planValue["asset_ref"]?.objectValue ?? [:]
        expectedAsset["role"] = .string("primary")
        guard requestValue["asset"] == .object(expectedAsset),
              requestValue["capsule"]?["asset"]?["asset_id"] == planValue["asset_ref"]?["asset_id"],
              requestValue["capsule"]?["asset"]?["asset_uid"] == planValue["asset_ref"]?["asset_uid"],
              requestValue["capsule"]?["asset"]?["version"] == planValue["asset_ref"]?["version"],
              requestValue["capsule"]?["asset"]?["judgment_version"] == planValue["asset_ref"]?["judgment_version"],
              requestValue["capsule"]?["access"] == planValue["asset_ref"]?["access"] else {
            throw protocolError("KDNA_HOST_ASSET_REF_MISMATCH", "Host request asset correlation failed.")
        }
        guard requestValue["runtime_contract"]?["capsule_version"] == .string(contractVersion),
              requestValue["capsule"]?["contract_version"] == .string(contractVersion) else {
            throw protocolError("KDNA_HOST_CAPSULE_CONTRACT_VERSION_MISMATCH", "Capsule version correlation failed.")
        }
        guard requestValue["runtime_contract"]?["capsule_digest_profile"] == .string(KDNARuntimeCapsuleCore.deliveryDigestProfile),
              requestValue["runtime_contract"]?["capsule_digest_profile_version"] == .string(KDNARuntimeCapsuleCore.deliveryDigestProfileVersion),
              requestValue["capsule"]?["digests"]?["profile"] == planValue["projection_request"]?["required_digest_profile"],
              requestValue["capsule"]?["digests"]?["profile_version"] == planValue["projection_request"]?["required_digest_profile_version"] else {
            throw protocolError("KDNA_HOST_PROJECTION_CONTRACT_MISMATCH", "Projection contract correlation failed.")
        }
        let expectedProjectionContract = KDNAJSONValue.object([
            "profile": planValue["projection_request"]?["profile"] ?? .null,
            "required_digest_profile": planValue["projection_request"]?["required_digest_profile"] ?? .null,
            "required_digest_profile_version": planValue["projection_request"]?["required_digest_profile_version"] ?? .null,
            "require_packaged_asset": planValue["projection_request"]?["require_packaged_asset"] ?? .null,
        ])
        guard requestValue["projection_contract"] == expectedProjectionContract,
              requestValue["capsule"]?["profile"] == requestValue["projection_contract"]?["profile"] else {
            throw protocolError("KDNA_HOST_PROJECTION_CONTRACT_MISMATCH", "Projection contract correlation failed.")
        }
        guard requestValue["result_contract"] == planValue["result_request"] else {
            throw protocolError("KDNA_HOST_RESULT_CONTRACT_MISMATCH", "Result contract differs from plan.")
        }
        guard requestValue["budget"] == planValue["budget"] else {
            throw protocolError("KDNA_HOST_BUDGET_MISMATCH", "Host budget differs from plan.")
        }
        guard requestValue["constraints"] == planValue["constraints"] else {
            throw protocolError("KDNA_HOST_CONSTRAINTS_MISMATCH", "Host constraints differ from plan.")
        }
        if enforceBudget {
            let projectionCount = try characterCount(requestValue["capsule"]!)
            let taskCount = try characterCount(requestValue["task"]!)
            let projectionLimit = try integer(
                requestValue["budget"]?["max_projection_chars"],
                path: "budget.max_projection_chars"
            )
            let taskLimit = try integer(
                requestValue["budget"]?["max_task_chars"],
                path: "budget.max_task_chars"
            )
            guard projectionCount <= projectionLimit,
                  taskCount <= taskLimit else {
                throw protocolError("KDNA_HOST_BUDGET_LIMIT_EXCEEDED", "Pre-Host projection or task budget exceeded.")
            }
        }
        try validateExpectedDigests(
            expected: planValue["asset_ref"]?["expected_digests"],
            observed: requestValue["capsule"]?["digests"]
        )
        let capsule = try KDNARuntimeCapsule(jsonValue: requestValue["capsule"]!)
        let recomputed = try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule)
        guard requestValue["runtime_contract"]?["capsule_delivery_digest"] == .string(recomputed) else {
            throw protocolError("KDNA_CAPSULE_DELIVERY_DIGEST_MISMATCH", "Capsule delivery digest P mismatch.")
        }
    }

    public static func validateAgentHostReceipt(
        _ receipt: KDNAAgentHostReceipt,
        request: KDNAAgentHostRequest
    ) throws {
        let value = receipt.jsonValue
        let requestValue = request.jsonValue
        guard value["protocol"] == requestValue["protocol"],
              value["protocol_version"] == requestValue["protocol_version"],
              value["request_id"] == requestValue["request_id"] else {
            throw protocolError("KDNA_HOST_REQUEST_ID_MISMATCH", "Host receipt request correlation failed.")
        }
        let runtime = value["runtime_receipt"]
        let senderP = requestValue["runtime_contract"]?["capsule_delivery_digest"]
        guard runtime?["sender_capsule_delivery_digest"] == senderP,
              runtime?["echoed_capsule_delivery_digest"] == runtime?["host_recomputed_capsule_delivery_digest"] else {
            throw protocolError("KDNA_HOST_CAPSULE_DELIVERY_DIGEST_MISMATCH", "Host receipt P evidence is inconsistent.")
        }
        let comparison = runtime?["capsule_delivery_comparison"]?.stringValue
        if comparison == "mismatched" {
            guard runtime?["host_recomputed_capsule_delivery_digest"] != senderP,
                  runtime?["provider_execution_status"] == .string("not_started"),
                  value["outcome"] == .null else {
                throw protocolError("KDNA_HOST_CAPSULE_DELIVERY_DIGEST_MISMATCH", "Mismatched P receipt is incoherent.")
            }
            return
        }
        let capsule = try KDNARuntimeCapsule(jsonValue: requestValue["capsule"]!)
        let recomputed = try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule)
        guard comparison == "matched", senderP == .string(recomputed),
              runtime?["host_recomputed_capsule_delivery_digest"] == senderP,
              runtime?["provider_execution_status"] != .string("not_started") else {
            throw protocolError("KDNA_HOST_CAPSULE_DELIVERY_DIGEST_MISMATCH", "Matched P receipt is incoherent.")
        }
        guard runtime?["capsule_version"] == requestValue["runtime_contract"]?["capsule_version"],
              runtime?["capsule_digest_profile"] == requestValue["runtime_contract"]?["capsule_digest_profile"],
              runtime?["capsule_digest_profile_version"] == requestValue["runtime_contract"]?["capsule_digest_profile_version"] else {
            throw protocolError("KDNA_HOST_CAPSULE_CONTRACT_VERSION_MISMATCH", "Receipt Capsule contract differs from request.")
        }
        if value["outcome"] != .null {
            let outcomeUsage = value["outcome"]?["usage"]
            if outcomeUsage == .null {
                guard runtime?["usage"]?["basis"] == .string("not_observed"),
                      runtime?["usage"]?["tokens_used"] == .null,
                      runtime?["usage"]?["model_calls"] == .null else {
                    throw protocolError("KDNA_HOST_USAGE_MISMATCH", "Receipt usage claims unobserved values.")
                }
            } else {
                guard runtime?["usage"]?["basis"] == .string("host_reported"),
                      runtime?["usage"]?["tokens_used"] == outcomeUsage?["tokens_used"],
                      runtime?["usage"]?["model_calls"] == outcomeUsage?["model_calls"] else {
                    throw protocolError("KDNA_HOST_USAGE_MISMATCH", "Receipt usage differs from outcome.")
                }
            }
        }
    }

    public static func deriveBudgetEvidence(
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        request: KDNAAgentHostRequest?,
        receipt: KDNAAgentHostReceipt?
    ) throws -> KDNAJSONValue {
        try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest)
        if let receipt {
            guard let request else {
                throw protocolError("KDNA_VALIDATION_CONTEXT_INVALID", "Receipt budget evidence requires its request.")
            }
            try validateAgentHostReceipt(receipt, request: request)
        }
        let limits = plan.jsonValue["budget"]!
        let projectionChars = try request.map { try characterCount($0.jsonValue["capsule"]!) }
        let taskChars = try characterCount(plan.jsonValue["task"]!)
        let usage = receipt?.jsonValue["runtime_receipt"]?["usage"]
        let elapsed = usage?["elapsed_ms"] ?? .null
        let tokens = usage?["tokens_used"] ?? .null
        let calls = usage?["model_calls"] ?? .null
        let actual: KDNAJSONValue = .object([
            "projection_chars": projectionChars.map { .number(Double($0)) } ?? .null,
            "task_chars": .number(Double(taskChars)),
            "elapsed_ms": elapsed,
            "elapsed_basis": usage?["elapsed_basis"] ?? .string("not_observed"),
            "tokens_used": tokens,
            "model_calls": calls,
            "usage_basis": usage?["basis"] ?? .string("not_observed"),
        ])
        var comparisons: [String: KDNAJSONValue] = [
            "projection_chars": .string(compare(
                projectionChars,
                limit: try optionalInteger(limits["max_projection_chars"], path: "budget.max_projection_chars")
            )),
            "task_chars": .string(compare(
                taskChars,
                limit: try optionalInteger(limits["max_task_chars"], path: "budget.max_task_chars")
            )),
            "elapsed_ms": .string(compare(
                try optionalInteger(elapsed, path: "runtime_receipt.usage.elapsed_ms"),
                limit: try optionalInteger(limits["deadline_ms"], path: "budget.deadline_ms")
            )),
            "tokens_used": .string(compare(
                try optionalInteger(tokens, path: "runtime_receipt.usage.tokens_used"),
                limit: try optionalInteger(limits["max_tokens"], path: "budget.max_tokens")
            )),
            "model_calls": .string(compare(
                try optionalInteger(calls, path: "runtime_receipt.usage.model_calls"),
                limit: try optionalInteger(limits["max_model_calls"], path: "budget.max_model_calls")
            )),
        ]
        let states = comparisons.values.compactMap(\.stringValue)
        comparisons["overall"] = .string(
            states.contains("exceeded") ? "exceeded" :
                states.contains("not_observed") ? "not_observed" : "within_limit"
        )
        return .object(["limits": limits, "actual": actual, "comparison": .object(comparisons)])
    }

    public static func validateJudgmentTrace(
        _ trace: KDNAJudgmentTrace,
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String] = coreCapsuleVersions,
        request: KDNAAgentHostRequest,
        receipt: KDNAAgentHostReceipt
    ) throws {
        try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest)
        let value = trace.jsonValue
        guard let overallStatus = value["overall_status"]?.stringValue,
              ["execution_completed", "execution_failed", "cancelled", "timed_out"]
                .contains(overallStatus) else {
            throw protocolError("KDNA_TRACE_TERMINAL_STATE_MISMATCH", "Trace terminal state does not match Host evidence.")
        }
        guard value["plan_ref"]?["plan_id"] == plan.jsonValue["plan_id"],
              value["plan_ref"]?["plan_digest_profile"] == plan.jsonValue["integrity"]?["profile"],
              value["plan_ref"]?["plan_digest_profile_version"] == plan.jsonValue["integrity"]?["profile_version"],
              value["plan_ref"]?["plan_digest"] == plan.jsonValue["integrity"]?["plan_digest"],
              value["plan_ref"]?["comparison"] == .string("matched") else {
            throw protocolError("KDNA_TRACE_PLAN_REF_MISMATCH", "Trace plan correlation failed.")
        }
        try validateTraceRuntimeAuthority(
            value,
            plan: plan,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        try validateAgentHostRequest(
            request,
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        try validateAgentHostReceipt(receipt, request: request)
        let negotiation = negotiateRuntimePair(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        guard negotiation.state == "selected",
              let selectedCapsuleVersion = negotiation.capsule_version,
              let selectedHostProtocol = negotiation.host_protocol,
              value["runtime_contract"]?["selected_capsule_version"] == .string(selectedCapsuleVersion),
              value["runtime_contract"]?["selected_host_protocol"] == .string(selectedHostProtocol),
              value["runtime_contract"]?["negotiation_state"] == .string("selected"),
              value["runtime_contract"]?["issue_code"] == .null else {
            throw protocolError("KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH", "Trace negotiation evidence failed.")
        }
        var assetIdentity = request.jsonValue["asset"]?.objectValue ?? [:]
        assetIdentity.removeValue(forKey: "expected_digests")
        assetIdentity.removeValue(forKey: "role")
        guard value["asset_identity"] == .object(assetIdentity) else {
            throw protocolError("KDNA_TRACE_ASSET_IDENTITY_MISMATCH", "Trace asset identity differs from request.")
        }
        guard value["digest_evidence"] == request.jsonValue["capsule"]?["digests"] else {
            throw protocolError("KDNA_TRACE_DIGEST_EVIDENCE_MISMATCH", "Trace A/C/E evidence differs from Capsule.")
        }
        let p = request.jsonValue["runtime_contract"]?["capsule_delivery_digest"]
        let runtimeReceipt = receipt.jsonValue["runtime_receipt"]
        guard value["capsule_delivery_evidence"]?["observed"] == p,
              value["capsule_delivery_evidence"]?["host_boundary_comparison"] == .string("matched"),
              value["capsule_delivery_evidence"]?["host_recomputed"] == p,
              value["capsule_delivery_evidence"]?["host_echoed"] == p,
              value["capsule_delivery_evidence"]?["request_id"] == request.jsonValue["request_id"],
              value["projection_actual"]?["profile"] == request.jsonValue["projection_contract"]?["profile"],
              value["projection_actual"]?["capsule_delivery_digest"] == p,
              value["projection_actual"]?["profile_deviated_from_plan"] == .bool(false) else {
            throw protocolError("KDNA_TRACE_CAPSULE_DELIVERY_DIGEST_MISMATCH", "Trace P evidence is inconsistent.")
        }
        guard value["host_receipt"] == receipt.jsonValue else {
            throw protocolError("KDNA_TRACE_HOST_RECEIPT_MISMATCH", "Trace does not contain the independent receipt.")
        }
        guard value["execution"]?["semantic_consumption"] == runtimeReceipt?["semantic_consumption"],
              value["execution"]?["model_identity"] == runtimeReceipt?["model_identity"],
              value["execution"]?["execution_status"] == runtimeReceipt?["provider_execution_status"] else {
            throw protocolError("KDNA_TRACE_EXECUTION_EVIDENCE_MISMATCH", "Trace execution evidence differs from receipt.")
        }
        let expectedBudget = try deriveBudgetEvidence(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            request: request,
            receipt: receipt
        )
        guard value["budget"] == expectedBudget else {
            throw protocolError("KDNA_TRACE_BUDGET_MISMATCH", "Trace budget evidence is not exact.")
        }
        if receipt.jsonValue["outcome"] == .null {
            guard value["result_ref"] == .null else {
                throw protocolError("KDNA_TRACE_RESULT_DIGEST_MISMATCH", "Trace claims a missing outcome.")
            }
        } else {
            let digest = try digestJCS(receipt.jsonValue["outcome"]!)
            guard value["result_ref"]?["shape"] == request.jsonValue["result_contract"]?["shape"],
                  value["result_ref"]?["result_digest"] == .string(digest) else {
                throw protocolError("KDNA_TRACE_RESULT_DIGEST_MISMATCH", "Trace result digest differs from outcome.")
            }
        }
        let providerStatus = runtimeReceipt?["provider_execution_status"]?.stringValue
        let expectedProviderStatus = [
            "execution_completed": "completed",
            "execution_failed": "failed",
            "cancelled": "cancelled",
            "timed_out": "timed_out",
        ][overallStatus]
        guard providerStatus == expectedProviderStatus,
              value["execution"]?["execution_status"]?.stringValue == expectedProviderStatus else {
            throw protocolError("KDNA_TRACE_TERMINAL_STATE_MISMATCH", "Trace terminal state differs from Host execution status.")
        }
        let budgetOverall = expectedBudget["comparison"]?["overall"]?.stringValue
        if overallStatus == "execution_completed" {
            guard receipt.jsonValue["outcome"] != .null,
                  value["errors"]?.arrayValue?.isEmpty == true,
                  budgetOverall != "exceeded" else {
                throw protocolError("KDNA_TRACE_TERMINAL_STATE_MISMATCH", "Completed trace contains failure evidence.")
            }
        } else if overallStatus == "timed_out" {
            guard receipt.jsonValue["outcome"] == .null,
                  value["result_ref"] == .null,
                  value["errors"]?.arrayValue?.isEmpty == false,
                  expectedBudget["comparison"]?["elapsed_ms"] == .string("exceeded") else {
                throw protocolError("KDNA_TRACE_BUDGET_MISMATCH", "Timed-out trace lacks exact deadline evidence.")
            }
        } else {
            guard receipt.jsonValue["outcome"] == .null,
                  value["result_ref"] == .null,
                  value["errors"]?.arrayValue?.isEmpty == false,
                  budgetOverall != "exceeded" else {
                throw protocolError("KDNA_TRACE_TERMINAL_STATE_MISMATCH", "Failed or cancelled trace evidence is incoherent.")
            }
        }
    }

    public static func validateBlockedJudgmentTrace(
        _ trace: KDNAJudgmentTrace,
        plan: KDNAConsumptionPlan,
        trustedPlanDigest: String,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String] = coreCapsuleVersions
    ) throws {
        try validateConsumptionPlan(plan, trustedPlanDigest: trustedPlanDigest)
        let value = trace.jsonValue
        guard value["overall_status"] == .string("blocked"),
              value["plan_ref"]?["plan_id"] == plan.jsonValue["plan_id"],
              value["plan_ref"]?["plan_digest_profile"] == plan.jsonValue["integrity"]?["profile"],
              value["plan_ref"]?["plan_digest_profile_version"] == plan.jsonValue["integrity"]?["profile_version"],
              value["plan_ref"]?["plan_digest"] == plan.jsonValue["integrity"]?["plan_digest"],
              value["plan_ref"]?["comparison"] == .string("matched") else {
            throw protocolError("KDNA_TRACE_PLAN_REF_MISMATCH", "Blocked trace plan correlation failed.")
        }
        try validateTraceRuntimeAuthority(
            value,
            plan: plan,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        let negotiation = negotiateRuntimePair(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            capabilities: capabilities,
            coreCapsuleVersions: coreCapsuleVersions
        )
        let runtime = value["runtime_contract"]
        if negotiation.state == "selected" {
            guard runtime?["negotiation_state"] == .string("not_started"),
                  runtime?["selected_capsule_version"] == .null,
                  runtime?["selected_host_protocol"] == .null,
                  runtime?["issue_code"] == .null else {
                throw protocolError("KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH", "Blocked trace invents a selected Host pair.")
            }
        } else {
            guard runtime?["negotiation_state"] == .string("blocked"),
                  runtime?["selected_capsule_version"] == .null,
                  runtime?["selected_host_protocol"] == .null,
                  runtime?["issue_code"] == negotiation.issue_code.map(KDNAJSONValue.string) else {
                throw protocolError("KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH", "Blocked trace issue differs from negotiation.")
            }
        }
        var assetIdentity = plan.jsonValue["asset_ref"]?.objectValue ?? [:]
        assetIdentity.removeValue(forKey: "expected_digests")
        guard value["asset_identity"] == .object(assetIdentity),
              value["host_receipt"] == .null,
              value["result_ref"] == .null,
              value["execution"]?["delivery_status"] == .string("not_delivered"),
              value["execution"]?["execution_status"] == .string("not_started"),
              value["capsule_delivery_evidence"]?["observed"] == .null,
              value["capsule_delivery_evidence"]?["sender_computed"] == .bool(false),
              value["capsule_delivery_evidence"]?["host_recomputed"] == .null,
              value["capsule_delivery_evidence"]?["host_echoed"] == .null,
              value["capsule_delivery_evidence"]?["host_boundary_comparison"] == .string("unavailable"),
              value["projection_actual"]?["profile"] == .null,
              value["projection_actual"]?["capsule_delivery_digest"] == .null,
              value["errors"]?.arrayValue?.isEmpty == false else {
            throw protocolError("KDNA_TRACE_UNDELIVERED_HOST_EVIDENCE", "Blocked trace contains invented Host evidence.")
        }
        for name in ["asset", "content", "runtime_entry_set"] {
            guard value["digest_evidence"]?[name]?["value"] == .null,
                  value["digest_evidence"]?[name]?["comparison"]?["state"] == .string("unavailable") else {
                throw protocolError("KDNA_TRACE_UNDELIVERED_HOST_EVIDENCE", "Blocked trace contains invented digest evidence.")
            }
        }
        let expectedBudget = try deriveBudgetEvidence(
            plan: plan,
            trustedPlanDigest: trustedPlanDigest,
            request: nil,
            receipt: nil
        )
        guard value["budget"] == expectedBudget else {
            throw protocolError("KDNA_TRACE_BUDGET_MISMATCH", "Blocked trace budget evidence is not exact.")
        }
    }

    private static func validateTraceRuntimeAuthority(
        _ trace: KDNAJSONValue,
        plan: KDNAConsumptionPlan,
        capabilities: KDNAAgentHostCapabilities,
        coreCapsuleVersions: [String]
    ) throws {
        let runtime = trace["runtime_contract"]
        guard runtime?["plan_capsule_versions"] == plan.jsonValue["projection_request"]?["accepted_capsule_versions"],
              runtime?["plan_host_protocols"] == plan.jsonValue["host_request"]?["accepted_protocols"],
              runtime?["core_capsule_versions"] == .array(coreCapsuleVersions.map { .string($0) }),
              runtime?["host_capabilities"] == capabilities.jsonValue else {
            throw protocolError(
                "KDNA_TRACE_NEGOTIATION_EVIDENCE_MISMATCH",
                "Trace Runtime authority differs from the independently supplied Plan, Core, or Host capabilities."
            )
        }
    }

    private static func computePlanDigest(_ value: KDNAJSONValue) throws -> String {
        guard var object = value.objectValue else {
            throw protocolError("KDNA_PLAN_INPUT_INVALID", "ConsumptionPlan digest input must be an object.")
        }
        object.removeValue(forKey: "integrity")
        return try digestJCS(.object(object))
    }

    private static func digestJCS(_ value: KDNAJSONValue) throws -> String {
        KDNARuntimeCapsuleCore.computeAssetDigest(try KDNAJCS.canonicalData(value))
    }

    private static func validateExpectedDigests(
        expected: KDNAJSONValue?,
        observed: KDNAJSONValue?
    ) throws {
        for name in ["asset", "content", "runtime_entry_set"] {
            guard let expectedValue = expected?[name], expectedValue != .null else { continue }
            let actual = observed?[name]
            guard actual?["value"] == expectedValue["value"],
                  actual?["basis"] == expectedValue["basis"],
                  actual?["comparison"]?["state"] == expectedValue["comparison"] else {
                throw protocolError("KDNA_HOST_DIGEST_EXPECTATION_MISMATCH", "Host digest expectation differs from Capsule.")
            }
            if expectedValue["comparison"] == .string("matched") {
                let source = expectedValue["source"]?.stringValue
                let against = source == "kdna.json.content_digest" ? "manifest_declaration" :
                    source == "checksums.json.entry_set_digest" ? "checksum_declaration" : "external_expected"
                guard actual?["comparison"]?["expected"] == expectedValue["value"],
                      actual?["comparison"]?["source"] == expectedValue["source"],
                      actual?["comparison"]?["against"] == .string(against) else {
                    throw protocolError("KDNA_HOST_DIGEST_EXPECTATION_MISMATCH", "Host digest source correlation failed.")
                }
            } else {
                guard actual?["comparison"]?["expected"] == .null,
                      actual?["comparison"]?["source"] == .null,
                      actual?["comparison"]?["against"] == .null else {
                    throw protocolError("KDNA_HOST_DIGEST_EXPECTATION_MISMATCH", "Uncompared digest claims an expectation.")
                }
            }
        }
    }

    private static func characterCount(_ value: KDNAJSONValue) throws -> Int {
        let count = try KDNAJCS.canonicalString(value).unicodeScalars.count
        guard Double(count) <= maximumExactJSONInteger else {
            throw unsafeIntegerError(path: "canonical_character_count")
        }
        return count
    }

    private static func integer(_ value: KDNAJSONValue?, path: String) throws -> Int {
        guard let result = try safeInteger(value, path: path, nullable: false) else {
            throw unsafeIntegerError(path: path)
        }
        return result
    }

    private static func optionalInteger(_ value: KDNAJSONValue?, path: String) throws -> Int? {
        try safeInteger(value, path: path, nullable: true)
    }

    // JavaScript is the canonical Runtime implementation. Keeping integers
    // inside Number.MAX_SAFE_INTEGER preserves exact cross-language meaning
    // and is stricter than the shared schemas without changing their bytes.
    private static let maximumExactJSONInteger = 9_007_199_254_740_991.0

    private static func safeInteger(
        _ value: KDNAJSONValue?,
        path: String,
        nullable: Bool
    ) throws -> Int? {
        guard let value else { throw unsafeIntegerError(path: path) }
        if value == .null {
            guard nullable else { throw unsafeIntegerError(path: path) }
            return nil
        }
        guard let number = value.numberValue,
              number.isFinite,
              number >= 0,
              number.rounded(.towardZero) == number,
              number <= maximumExactJSONInteger,
              let exact = Int(exactly: number) else {
            throw unsafeIntegerError(path: path)
        }
        return exact
    }

    private static func requireSafeRuntimeIntegers(
        _ value: KDNAJSONValue,
        kind: SchemaKind
    ) throws {
        switch kind {
        case .plan:
            try requireSafeBudgetIntegers(value["budget"], path: "budget")
        case .request:
            try requireSafeBudgetIntegers(value["budget"], path: "budget")
        case .receipt:
            try requireSafeReceiptIntegers(value, path: "receipt")
        case .trace:
            try requireSafeBudgetIntegers(value["budget"]?["limits"], path: "budget.limits")
            try requireSafeBudgetActualIntegers(value["budget"]?["actual"], path: "budget.actual")
            if let hostReceipt = value["host_receipt"], hostReceipt != .null {
                try requireSafeReceiptIntegers(hostReceipt, path: "host_receipt")
            }
        case .capabilities:
            break
        }
    }

    private static func requireSafeBudgetIntegers(
        _ budget: KDNAJSONValue?,
        path: String
    ) throws {
        for name in ["max_projection_chars", "max_task_chars", "deadline_ms"] {
            _ = try safeInteger(budget?[name], path: "\(path).\(name)", nullable: false)
        }
        for name in ["max_tokens", "max_model_calls"] {
            _ = try safeInteger(budget?[name], path: "\(path).\(name)", nullable: true)
        }
    }

    private static func requireSafeBudgetActualIntegers(
        _ actual: KDNAJSONValue?,
        path: String
    ) throws {
        _ = try safeInteger(actual?["projection_chars"], path: "\(path).projection_chars", nullable: true)
        _ = try safeInteger(actual?["task_chars"], path: "\(path).task_chars", nullable: false)
        _ = try safeInteger(actual?["elapsed_ms"], path: "\(path).elapsed_ms", nullable: true)
        _ = try safeInteger(actual?["tokens_used"], path: "\(path).tokens_used", nullable: true)
        _ = try safeInteger(actual?["model_calls"], path: "\(path).model_calls", nullable: true)
    }

    private static func requireSafeReceiptIntegers(
        _ receipt: KDNAJSONValue,
        path: String
    ) throws {
        let usage = receipt["runtime_receipt"]?["usage"]
        _ = try safeInteger(
            usage?["elapsed_ms"],
            path: "\(path).runtime_receipt.usage.elapsed_ms",
            nullable: false
        )
        _ = try safeInteger(
            usage?["tokens_used"],
            path: "\(path).runtime_receipt.usage.tokens_used",
            nullable: true
        )
        _ = try safeInteger(
            usage?["model_calls"],
            path: "\(path).runtime_receipt.usage.model_calls",
            nullable: true
        )
        if let outcomeUsage = receipt["outcome"]?["usage"], outcomeUsage != .null {
            _ = try safeInteger(
                outcomeUsage["tokens_used"],
                path: "\(path).outcome.usage.tokens_used",
                nullable: false
            )
            _ = try safeInteger(
                outcomeUsage["model_calls"],
                path: "\(path).outcome.usage.model_calls",
                nullable: false
            )
        }
    }

    private static func unsafeIntegerError(path: String) -> KDNARuntimeContractError {
        protocolError(
            "KDNA_RUNTIME_INTEGER_UNSAFE",
            "Runtime integer at \(path) is outside the exact cross-language range."
        )
    }

    private static func compare(_ value: Int?, limit: Int?) -> String {
        guard let limit else { return "not_limited" }
        guard let value else { return "not_observed" }
        return value <= limit ? "within_limit" : "exceeded"
    }

    private static func strings(_ value: KDNAJSONValue?) -> [String] {
        value?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    private static func validDigest(_ value: String) -> Bool {
        value.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    private static func blocked(_ code: String) -> KDNARuntimeNegotiation {
        KDNARuntimeNegotiation(state: "blocked", capsule_version: nil, host_protocol: nil, issue_code: code)
    }

    private static func protocolError(_ code: String, _ message: String) -> KDNARuntimeContractError {
        KDNARuntimeContractError(code: code, message: message)
    }
}

private extension KDNARuntimeCapsule {
    init(jsonValue: KDNAJSONValue) throws {
        let data = try JSONSerialization.data(withJSONObject: jsonValue.anyValue)
        self = try JSONDecoder().decode(KDNARuntimeCapsule.self, from: data)
    }
}

private extension KDNAJSONValue {
    var numberValue: Double? {
        guard case .number(let value) = self else { return nil }
        return value
    }
}
