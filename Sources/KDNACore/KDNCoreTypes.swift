//  KDNACore — Swift implementation of the KDNA Protocol v1.0-rc
//  https://github.com/aikdna/kdna

import Foundation

// MARK: - Core Data Types

public struct KDNADomain: Codable {
    public let core: KDNCoreData
    public let patterns: KDNAPatternsData
    public var scenarios: KDNAScenariosData?
    public var cases: KDNACasesData?
    public var reasoning: KDNAReasoningData?
    public var evolution: KDNAEvolutionData?
}

public struct KDNCoreData: Codable {
    public let meta: KDNAMeta
    public let stances: [KDNAStance]?
    public let axioms: [KDNAAxiom]?
    public let ontology: [KDNAConcept]?
    public let frameworks: [KDNAFramework]?
    public let core_structure: [String]?
    public let trigger_signals: [String]?

    // Phase 1a — Judgment Model fields
    public let highest_question: String?
    public let worldview: [String]?
    public let judgment_role: KDNAJudgmentRole?
    public let value_order: [String]?

    enum CodingKeys: String, CodingKey {
        case meta, stances, axioms, ontology, frameworks, core_structure, trigger_signals
        case highest_question, worldview, judgment_role, value_order
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        meta = try container.decode(KDNAMeta.self, forKey: .meta)
        stances = try container.decodeIfPresent([KDNAStance].self, forKey: .stances)
        axioms = try container.decodeIfPresent([KDNAAxiom].self, forKey: .axioms)
        ontology = try container.decodeIfPresent([KDNAConcept].self, forKey: .ontology)
        frameworks = try container.decodeIfPresent([KDNAFramework].self, forKey: .frameworks)
        core_structure = try? container.decodeIfPresent([String].self, forKey: .core_structure)
        trigger_signals = try container.decodeIfPresent([String].self, forKey: .trigger_signals)

        // Phase 1a
        highest_question = try container.decodeIfPresent(String.self, forKey: .highest_question)
        worldview = try container.decodeIfPresent([String].self, forKey: .worldview)
        judgment_role = try container.decodeIfPresent(KDNAJudgmentRole.self, forKey: .judgment_role)
        value_order = try container.decodeIfPresent([String].self, forKey: .value_order)
    }
}

/// A stance entry that supports both legacy string format and new object format with applies_when/does_not_apply_when.
public struct KDNAStance: Codable {
    public let stance: String
    public let applies_when: [String]?
    public let does_not_apply_when: [String]?

    enum CodingKeys: String, CodingKey {
        case stance, applies_when, does_not_apply_when
    }

    public init(from decoder: Decoder) throws {
        // Try legacy string format first
        if let container = try? decoder.singleValueContainer(),
           let str = try? container.decode(String.self) {
            self.stance = str
            self.applies_when = nil
            self.does_not_apply_when = nil
            return
        }
        // Object format
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.stance = try container.decode(String.self, forKey: .stance)
        self.applies_when = try container.decodeIfPresent([String].self, forKey: .applies_when)
        self.does_not_apply_when = try container.decodeIfPresent([String].self, forKey: .does_not_apply_when)
    }
}

public struct KDNAMeta: Codable {
    public let version: String
    public let domain: String
    public let created: String
    public let purpose: String
    public let load_condition: String

    enum CodingKeys: String, CodingKey {
        case version, domain, created, purpose, load_condition
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(String.self, forKey: .version) ?? "unknown"
        domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? "unknown"
        created = try container.decodeIfPresent(String.self, forKey: .created) ?? ""
        purpose = try container.decodeIfPresent(String.self, forKey: .purpose) ?? "Domain-specific judgment support."
        load_condition = try container.decodeIfPresent(String.self, forKey: .load_condition) ?? "always"
    }
}

// MARK: - Phase 1a — Judgment Model Types

public struct KDNAJudgmentRole: Codable {
    public let acts_as: String
    public let does_not_act_as: String
    public let responsibility: String

    public init(acts_as: String, does_not_act_as: String, responsibility: String) {
        self.acts_as = acts_as
        self.does_not_act_as = does_not_act_as
        self.responsibility = responsibility
    }
}

public struct KDNAAxiom: Codable {
    public let id: String?
    public let one_sentence: String
    public let full_statement: String
    public let why: String

    // Phase 1a — governance fields (formerly recommended, now required for new domains)
    public let applies_when: [String]?
    public let does_not_apply_when: [String]?
    public let failure_risk: String?
    public let confidence: String?
    public let evidence_type: [String]?

    public init(
        id: String? = nil,
        one_sentence: String,
        full_statement: String,
        why: String,
        applies_when: [String]? = nil,
        does_not_apply_when: [String]? = nil,
        failure_risk: String? = nil,
        confidence: String? = nil,
        evidence_type: [String]? = nil
    ) {
        self.id = id
        self.one_sentence = one_sentence
        self.full_statement = full_statement
        self.why = why
        self.applies_when = applies_when
        self.does_not_apply_when = does_not_apply_when
        self.failure_risk = failure_risk
        self.confidence = confidence
        self.evidence_type = evidence_type
    }
}

public struct KDNAConcept: Codable {
    public let id: String?
    public let one_sentence: String
    public let essence: String
    public let boundary: String
    public let trigger_signal: String
}

public struct KDNAFramework: Codable {
    public let id: String?
    public let name: String
    public let when_to_use: String?
    public let steps: [String]?
}

// MARK: - Phase 1a — Patterns Extensions

public struct KDNAPatternsData: Codable {
    public let meta: KDNAMeta?
    public let terminology: KDNATerminology?
    public let misunderstandings: [KDNAMisunderstanding]?
    public let self_check: [String]?

    // Phase 1a
    public let aesthetic_preferences: [KDNAAestheticPreference]?
    public let boundaries: [KDNABoundary]?
    public let risk_model: KDNARiskModel?
    public let counterexamples: [KDNACounterexample]?

    enum CodingKeys: String, CodingKey {
        case meta, terminology, misunderstandings, self_check
        case aesthetic_preferences, boundaries, risk_model, counterexamples
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        meta = try container.decodeIfPresent(KDNAMeta.self, forKey: .meta)
        terminology = try container.decodeIfPresent(KDNATerminology.self, forKey: .terminology)
        misunderstandings = try container.decodeIfPresent([KDNAMisunderstanding].self, forKey: .misunderstandings)
        self_check = try container.decodeIfPresent([String].self, forKey: .self_check)

        aesthetic_preferences = try container.decodeIfPresent([KDNAAestheticPreference].self, forKey: .aesthetic_preferences)
        boundaries = try container.decodeIfPresent([KDNABoundary].self, forKey: .boundaries)
        risk_model = try container.decodeIfPresent(KDNARiskModel.self, forKey: .risk_model)
        counterexamples = try container.decodeIfPresent([KDNACounterexample].self, forKey: .counterexamples)
    }
}

public struct KDNAAestheticPreference: Codable {
    public let prefer: String
    public let avoid: String
    public let signals_good: [String]?
    public let signals_bad: [String]?
}

public struct KDNABoundary: Codable {
    public let rule: String
    public let why: String
    public let must_not_do: String
    public let acceptable_exception: String?
}

public struct KDNARiskModel: Codable {
    public let highest_risk_errors: [String]?
    public let acceptable_errors: [String]?
    public let must_block_when: String?
    public let warn_when: String?
}

public struct KDNACounterexample: Codable {
    public let bad_example: String
    public let why_bad: String
    public let violated_axioms: [String]?
    public let better_direction: String
}

public struct KDNATerminology: Codable {
    public let standard_terms: [KDNAStandardTerm]?
    public let banned_terms: [KDNABannedTerm]?
}

public struct KDNAStandardTerm: Codable {
    public let term: String
    public let definition: String
}

public struct KDNABannedTerm: Codable {
    public let term: String
    public let why: String
    public let replace_with: String
}

public struct KDNAMisunderstanding: Codable {
    public let id: String?
    public let wrong: String
    public let correct: String
    public let key_distinction: String
    public let why: String
}

public struct KDNAScenariosData: Codable {
    public let meta: KDNAMeta?
    public let scenes: [KDNAPromptScene]?
}

/// A scenario entry supporting Phase 1b upgrades:
/// - trigger_signal (legacy single) → trigger_signals (array)
/// - negative_signals, classification_rule, risk_level, expected_judgment_shift
public struct KDNAPromptScene: Codable {
    public let id: String?
    public let name: String
    public let trigger_signals: [String]?
    public let negative_signals: [String]?
    public let classification_rule: String?
    public let risk_level: String?
    public let expected_judgment_shift: String?

    enum CodingKeys: String, CodingKey {
        case id, name, trigger_signal, trigger_signals
        case negative_signals, classification_rule, risk_level, expected_judgment_shift
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        negative_signals = try container.decodeIfPresent([String].self, forKey: .negative_signals)
        classification_rule = try container.decodeIfPresent(String.self, forKey: .classification_rule)
        risk_level = try container.decodeIfPresent(String.self, forKey: .risk_level)
        expected_judgment_shift = try container.decodeIfPresent(String.self, forKey: .expected_judgment_shift)

        // Backward compatibility: accept both trigger_signal (single) and trigger_signals (array)
        if let signals = try? container.decode([String].self, forKey: .trigger_signals) {
            trigger_signals = signals
        } else if let single = try? container.decode(String.self, forKey: .trigger_signal) {
            trigger_signals = [single]
        } else {
            trigger_signals = nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(trigger_signals, forKey: .trigger_signals)
        try container.encodeIfPresent(negative_signals, forKey: .negative_signals)
        try container.encodeIfPresent(classification_rule, forKey: .classification_rule)
        try container.encodeIfPresent(risk_level, forKey: .risk_level)
        try container.encodeIfPresent(expected_judgment_shift, forKey: .expected_judgment_shift)
    }
}

public struct KDNACasesData: Codable {
    public let meta: KDNAMeta?
    public let cases: [KDNAPromptCase]?
}

/// A case entry with Phase 1b upgrades:
/// - judgment_path, good_response, bad_response, why_good, why_bad, triggered_axioms
public struct KDNAPromptCase: Codable {
    public let id: String?
    public let title: String
    public let context: String
    public let what_happened: String
    public let what_was_learned: String
    public let structural_pattern: String
    public let scene_id: String?

    // Phase 1b
    public let judgment_path: String?
    public let good_response: String?
    public let bad_response: String?
    public let why_good: String?
    public let why_bad: String?
    public let triggered_axioms: [String]?

    enum CodingKeys: String, CodingKey {
        case id, title, context, what_happened, what_was_learned, structural_pattern, scene_id
        case judgment_path, good_response, bad_response, why_good, why_bad, triggered_axioms
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        context = try container.decode(String.self, forKey: .context)
        what_happened = try container.decode(String.self, forKey: .what_happened)
        what_was_learned = try container.decode(String.self, forKey: .what_was_learned)
        structural_pattern = try container.decode(String.self, forKey: .structural_pattern)
        scene_id = try container.decodeIfPresent(String.self, forKey: .scene_id)

        // Phase 1b
        judgment_path = try container.decodeIfPresent(String.self, forKey: .judgment_path)
        good_response = try container.decodeIfPresent(String.self, forKey: .good_response)
        bad_response = try container.decodeIfPresent(String.self, forKey: .bad_response)
        why_good = try container.decodeIfPresent(String.self, forKey: .why_good)
        why_bad = try container.decodeIfPresent(String.self, forKey: .why_bad)
        triggered_axioms = try container.decodeIfPresent([String].self, forKey: .triggered_axioms)
    }
}

public struct KDNAReasoningData: Codable {
    public let meta: KDNAMeta?
    public let reasoning_chains: [KDNAReasoningChain]?
}

public struct KDNAReasoningChain: Codable {
    public let id: String?
    public let one_sentence: String
    public let logic: String
    public let so_what: String
}

public struct KDNAEvolutionData: Codable {
    public let meta: KDNAMeta?
    public let stages: [KDNAEvolutionStage]?
    public let evolution_layers: [KDNAEvolutionLayer]?
    public let measurement: [KDNAMeasurement]?
}

public struct KDNAEvolutionStage: Codable {
    public let id: String?
    public let name: String
    public let description: String
}

public struct KDNAEvolutionLayer: Codable {
    public let name: String
    public let capability: String
    public let from_stage: String
    public let to_stage: String
}

public struct KDNAMeasurement: Codable {
    public let what: String
    public let how: String
    public let threshold: String
}

// MARK: - Pipeline Types

public enum KDNASystemPromptStrategy: String, Codable, CaseIterable {
    case domainFirst
    case personaFirst
    case compactDomain
    case strictJudgment
}

public struct KDNAPreFilterResult {
    public let shouldBlock: Bool
    public let blockReason: String?
    public let bannedTerms: [BannedTermMatch]
    public let signals: [String]
}

public struct BannedTermMatch {
    public let term: String
    public let replaceWith: String
    public let why: String
    public let sourceDomain: String
}

public struct KDNAPostValidateResult {
    public let passed: Bool
    public let bannedTerms: [BannedTermMatch]
    public let selfChecksFailed: [String]
    public let misunderstandings: [String]
}

public struct KDNADomainValidationResult {
    public let valid: Bool
    public let errors: [String]
    public let warnings: [String]
    public let fileCount: Int
    public let schemaOK: Bool
}

public struct KDNAJudgment {
    public let preFilter: KDNAPreFilterResult?
    public let postValidate: KDNAPostValidateResult?
    public let domainLoaded: Bool
    public let axiomsTriggered: [String]
}

// MARK: - Manifest Types

/// Parsed kdna.json manifest for a KDNA domain asset.
/// Aligns with SPEC.md v1.0-rc Section 3.4
public struct KDNAManifest: Codable {
    public let kdna_spec: String
    public let name: String
    public let version: String
    public let status: String?
    public let access: String?
    public let language: [String]?
    public let author: KDNAManifestAuthor?
    public let license: KDNAManifestLicense?
    public let description: String?
    public let keywords: [String]?
    public let core_insight: String?
    public let eval_score: Double?
    public let test_count: Int?
    public let quality_badge: String?
}

public struct KDNAManifestAuthor: Codable {
    public let name: String
    public let id: String
}

public struct KDNAManifestLicense: Codable {
    public let type: String
    public let url: String?
}
