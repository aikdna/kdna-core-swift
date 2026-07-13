import Foundation

/// KDNA Judgment Trace 0.9 Candidate — wire-compatible with kdna-cli trace JSON.
/// Supports both 0.9.0 (trace_version) and legacy 1.0.0 (kdna_trace).
/// Per architecture: SDKs consume the same contract; they do not invent routing.
public struct Trace: Codable, Sendable {
    // Version field — 0.9 uses "trace_version"; legacy 1.0 uses "kdna_trace"
    public let trace_version: String?
    public let kdna_trace: String?
    public let trace_id: String
    public let timestamp: String
    public let mode: String?

    // Plan reference (0.9)
    public let plan_id: String?

    // Legacy 1.0 fields (backward compat)
    public let operation: String?
    public let decision: TraceDecision?

    // 0.9 Single-asset identity
    public let asset_identity: AssetIdentity?

    // 0.9 Cluster identity
    public let assets_loaded: [AssetLoaded]?
    public let cluster_identity: ClusterIdentity?

    // 0.9 Execution details
    public let applicability_actual: ApplicabilityActual?
    public let projection_actual: ProjectionActual?
    public let selection_actual: SelectionActual?
    public let execution: Execution?

    // 0.9 Result + Cost
    public let result_ref: ResultRef?
    public let cost: TraceCost?

    // 0.9 Evaluation
    public let evaluation: Evaluation?
    public let source_attribution: [SourceAttribution]?
    public let conflicts: [TraceConflict]?

    // 0.9 Provenance
    public let provenance: TraceProvenance?

    // 0.9 Messages
    public let errors: [String]?
    public let warnings: [String]?

    // Metadata
    public let metadata: [String: String]?

    public var version: String {
        trace_version ?? kdna_trace ?? "unknown"
    }

    public var is09: Bool {
        trace_version == "0.9.0"
    }

    public static func fromJSON(_ data: Data) throws -> Trace {
        let decoder = JSONDecoder()
        return try decoder.decode(Trace.self, from: data)
    }
}

// ── 0.9 Types ────────────────────────────────────────────────────────

public struct AssetIdentity: Codable, Sendable {
    public let asset_id: String
    public let version: String
    public let digest: String
    public let digest_verified: Bool
    public let signature_verified: Bool?
    public let revocation_status: String?
    public let authorization: String?
    public let projection_digest: String?
}

public struct AssetLoaded: Codable, Sendable {
    public let asset_id: String
    public let version: String?
    public let digest: String?
    public let role: String
    public let weight: Double
    public let digest_verified: Bool
    public let authorization: String?
    public let projection_digest: String?
    public let contribution_hypothesis: String?
    public let contribution_fulfilled: Bool?
    public let failure_reason: String?
}

public struct ClusterIdentity: Codable, Sendable {
    public let cluster_id: String
    public let version: String?
    public let manifest_digest: String?
}

public struct ApplicabilityActual: Codable, Sendable {
    public let decision: String
    public let confidence: String?
    public let boundary_respected: Bool
    public let deviated_from_plan: Bool?
}

public struct ProjectionActual: Codable, Sendable {
    public let shape: String
    public let content_digest: String?
    public let shape_deviated_from_plan: Bool?
}

public struct SelectionActual: Codable, Sendable {
    public let primary: String?
    public let advisors: [String]?
    public let rejected: [SelectionRejected]?
    public let deviated_from_plan: Bool?
}

public struct SelectionRejected: Codable, Sendable {
    public let asset_id: String
    public let reason: String?
}

public struct Execution: Codable, Sendable {
    public let status: String
    public let runner_id: String?
    public let runner_version: String?
    public let model: String?
    public let started_at: String?
    public let completed_at: String?
    public let duration_ms: Int?
    public let attempts: Int?
}

public struct ResultRef: Codable, Sendable {
    public let result_hash: String?
    public let result_shape: String?
    public let answer_summary: String?
    public let result_stored: Bool?
}

public struct SourceAttribution: Codable, Sendable {
    public let asset_id: String
    public let axioms_triggered: Int
    public let transfer_depth: TransferDepth?
}

public struct TransferDepth: Codable, Sendable {
    public let operationalized: Int
    public let referenced: Int
    public let mentioned: Int
}

public struct Evaluation: Codable, Sendable {
    public let self_checks: [SelfCheck]?
    public let violations: [Violation]?
    public let banned_terms_detected: [String]?
}

public struct SelfCheck: Codable, Sendable {
    public let check_id: String
    public let passed: Bool
    public let detail: String?
}

public struct Violation: Codable, Sendable {
    public let type: String
    public let severity: String
    public let description: String?
    public let asset_id: String?
}

public struct TraceConflict: Codable, Sendable {
    public let type: String
    public let assets: [String]?
    public let description: String?
    public let severity: String?
    public let resolution: String?
}

// ── Legacy 1.0 Types (backward compat) ────────────────────────────────

public struct TraceDecision: Codable, Sendable {
    public let primary: TraceDomainEntry?
    public let advisors: [TraceDomainEntry]?
    public let rejected: [TraceRejectedEntry]?
    public let budget_profile: String?
    public let confidence: String?
    public let abstain_reason: String?
}

public struct TraceDomainEntry: Codable, Sendable {
    public let domain_id: String
    public let weight: Double
    public let reason: String?
    public let role: String?
}

public struct TraceRejectedEntry: Codable, Sendable {
    public let domain_id: String
    public let reason: String?
}

public struct TraceCost: Codable, Sendable {
    public let tokens_consumed: Int?
    public let tokens_used: Int?
    public let chars_consumed: Int?
    public let assets_loaded: Int?
    public let model_calls: Int?
    public let budget_profile: String?
    public let over_budget: Bool?
    public let over_budget_reason: String?
}

public struct TraceProvenance: Codable, Sendable {
    public let plan_digest: String?
    public let route_card_version: String?
    public let consumer_index_version: String?
    public let policy_input_hash: String?
    public let policy_hash: String?
    public let cluster_manifest_digest: String?
}

// ── Projector ─────────────────────────────────────────────────────────

public struct TraceProjector: Sendable {
    public let trace: Trace

    public init(trace: Trace) {
        self.trace = trace
    }

    // ── 0.9 primary query ────────────────────────────────────────────
    public var primaryDomainId: String? {
        // 0.9: single asset
        if let aid = trace.asset_identity?.asset_id { return aid }
        // 0.9: cluster (first primary in assets_loaded)
        if let primary = trace.assets_loaded?.first(where: { $0.role == "primary" }) {
            return primary.asset_id
        }
        // 0.9: selection
        if let sel = trace.selection_actual?.primary { return sel }
        // legacy
        return trace.decision?.primary?.domain_id
    }

    public var advisorDomainIds: [String] {
        trace.assets_loaded?.filter { $0.role == "advisor" }.map { $0.asset_id }
            ?? trace.selection_actual?.advisors
            ?? trace.decision?.advisors?.map { $0.domain_id }
            ?? []
    }

    public var confidence: String {
        trace.applicability_actual?.confidence
            ?? trace.decision?.confidence
            ?? "unknown"
    }

    public var executionStatus: String {
        trace.execution?.status ?? "unknown"
    }

    public var isOverBudget: Bool {
        trace.cost?.over_budget ?? false
    }

    public var answerSummary: String {
        trace.result_ref?.answer_summary ?? ""
    }

    public var selfCheckSummary: (passed: Int, total: Int) {
        let checks = trace.evaluation?.self_checks ?? []
        return (checks.filter { $0.passed }.count, checks.count)
    }

    public var hasWarnings: Bool {
        (trace.warnings?.count ?? 0) > 0
    }

    public func projectAsAnswer() -> AnswerProjection {
        AnswerProjection(
            primary: primaryDomainId,
            confidence: confidence,
            advisors: advisorDomainIds,
            isOverBudget: isOverBudget,
            answerSummary: answerSummary,
            status: executionStatus,
            mode: trace.mode ?? "single"
        )
    }

    public func projectAsCompact() -> CompactProjection {
        CompactProjection(
            primary: primaryDomainId ?? "none",
            advisorCount: advisorDomainIds.count,
            costTokens: trace.cost?.tokens_used ?? trace.cost?.tokens_consumed ?? 0,
            status: executionStatus,
            mode: trace.mode ?? "single"
        )
    }
}

public struct AnswerProjection: Codable, Sendable {
    public let primary: String?
    public let confidence: String
    public let advisors: [String]
    public let isOverBudget: Bool
    public let answerSummary: String
    public let status: String
    public let mode: String
}

public struct CompactProjection: Codable, Sendable {
    public let primary: String
    public let advisorCount: Int
    public let costTokens: Int
    public let status: String
    public let mode: String
}
