import Foundation

/// KDNA Consumption Trace v1 — wire-compatible with kdna-cli trace JSON output.
/// Per architecture: SDKs consume the same contract, they do not invent their own routing.
public struct Trace: Codable, Sendable {
    public let kdna_trace: String
    public let trace_id: String
    public let timestamp: String
    public let operation: String
    public let decision: TraceDecision
    public let cost: TraceCost?
    public let projection: TraceProjection?
    public let provenance: TraceProvenance?

    public static func fromJSON(_ data: Data) throws -> Trace {
        let decoder = JSONDecoder()
        return try decoder.decode(Trace.self, from: data)
    }
}

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
    public let tokens_consumed: Int
    public let chars_consumed: Int
    public let assets_loaded: Int
    public let over_budget: Bool
}

public struct TraceProjection: Codable, Sendable {
    public let shape: String
}

public struct TraceProvenance: Codable, Sendable {
    public let route_card_version: String?
    public let consumer_index_version: String?
    public let policy_input_hash: String?
}

/// Projects a loaded KDNA asset through a Trace into a consumable form.
/// Consumes the trace contract — does NOT re-implement routing logic.
public struct TraceProjector: Sendable {
    public let trace: Trace

    public init(trace: Trace) {
        self.trace = trace
    }

    public var primaryDomainId: String? {
        trace.decision.primary?.domain_id
    }

    public var advisorDomainIds: [String] {
        trace.decision.advisors?.map { $0.domain_id } ?? []
    }

    public var confidence: String {
        trace.decision.confidence ?? "unknown"
    }

    public var isOverBudget: Bool {
        trace.cost?.over_budget ?? false
    }

    public func projectAsAnswer() -> AnswerProjection {
        AnswerProjection(
            primary: trace.decision.primary?.domain_id,
            confidence: confidence,
            advisors: advisorDomainIds,
            isOverBudget: isOverBudget
        )
    }

    public func projectAsCompact() -> CompactProjection {
        CompactProjection(
            primary: trace.decision.primary?.domain_id ?? "none",
            advisorCount: advisorDomainIds.count,
            costTokens: trace.cost?.tokens_consumed ?? 0
        )
    }
}

public struct AnswerProjection: Codable, Sendable {
    public let primary: String?
    public let confidence: String
    public let advisors: [String]
    public let isOverBudget: Bool
}

public struct CompactProjection: Codable, Sendable {
    public let primary: String
    public let advisorCount: Int
    public let costTokens: Int
}
