//  KDNACore — Swift implementation of KDNA judgment tooling
//  https://github.com/aikdna/kdna

import Foundation

/// Validates KDNA domain structure and cross-file consistency.
/// Swift port of @aikdna/kdna-core validate-pure.js and lint-pure.js
public class KDNADomainValidator {

    /// Lint a KDNA domain from a loaded domain object.
    public static func lintDomain(_ domain: KDNADomain) -> (errors: [String], warnings: [String]) {
        var errors: [String] = []
        var warnings: [String] = []

        let core = domain.core

        // Check required fields in core
        if core.axioms == nil || core.axioms?.isEmpty == true {
            errors.append("KDNA_Core.json: missing or empty 'axioms'")
        }
        if core.ontology == nil || core.ontology?.isEmpty == true {
            errors.append("KDNA_Core.json: missing or empty 'ontology'")
        }
        if core.frameworks == nil || core.frameworks?.isEmpty == true {
            errors.append("KDNA_Core.json: missing or empty 'frameworks'")
        }
        if core.stances == nil || core.stances?.isEmpty == true {
            errors.append("KDNA_Core.json: missing or empty 'stances'")
        }

        // Check required fields in patterns
        let patterns = domain.patterns
        if patterns.terminology == nil {
            warnings.append("KDNA_Patterns.json: missing 'terminology'")
        }
        if patterns.misunderstandings == nil || patterns.misunderstandings?.isEmpty == true {
            warnings.append("KDNA_Patterns.json: missing or empty 'misunderstandings'")
        }
        if patterns.self_check == nil || patterns.self_check?.isEmpty == true {
            warnings.append("KDNA_Patterns.json: missing or empty 'self_check'")
        }

        // Judgment governance — Check governance fields on axioms (recommended, not blocking old domains)
        if let axioms = core.axioms {
            let vaguePhrases = [
                "be helpful", "be professional", "be accurate", "best practices",
                "user-centric", "customer-focused", "excellence", "innovation",
            ]
            for (i, axiom) in axioms.enumerated() {
                let text = "\(axiom.one_sentence) \(axiom.full_statement)".lowercased()
                for phrase in vaguePhrases {
                    if text.contains(phrase) {
                        warnings.append("KDNA_Core.json.axioms[\(i)]: contains vague phrase '\(phrase)'")
                    }
                }
                if axiom.applies_when == nil || axiom.applies_when?.isEmpty == true {
                    warnings.append("KDNA_Core.json.axioms[\(i)]: missing 'applies_when' (Judgment governance recommended)")
                }
                if axiom.does_not_apply_when == nil || axiom.does_not_apply_when?.isEmpty == true {
                    warnings.append("KDNA_Core.json.axioms[\(i)]: missing 'does_not_apply_when' (Judgment governance recommended)")
                }
                if axiom.failure_risk == nil || axiom.failure_risk?.isEmpty == true {
                    warnings.append("KDNA_Core.json.axioms[\(i)]: missing 'failure_risk' (Judgment governance recommended)")
                }
                if axiom.confidence == nil || axiom.confidence?.isEmpty == true {
                    warnings.append("KDNA_Core.json.axioms[\(i)]: missing 'confidence' (Judgment governance recommended)")
                }
            }
        }

        // Judgment governance — Judgment Model fields (recommended)
        if core.highest_question == nil || core.highest_question?.isEmpty == true {
            warnings.append("KDNA_Core.json: missing 'highest_question' (Judgment governance recommended)")
        }
        if core.worldview == nil || core.worldview?.isEmpty == true {
            warnings.append("KDNA_Core.json: missing 'worldview' (Judgment governance recommended)")
        }
        if let role = core.judgment_role {
            if role.acts_as.isEmpty {
                warnings.append("KDNA_Core.json.judgment_role: 'acts_as' is empty")
            }
            if role.does_not_act_as.isEmpty {
                warnings.append("KDNA_Core.json.judgment_role: 'does_not_act_as' is empty")
            }
            if role.responsibility.isEmpty {
                warnings.append("KDNA_Core.json.judgment_role: 'responsibility' is empty")
            }
        } else {
            warnings.append("KDNA_Core.json: missing 'judgment_role' (Judgment governance recommended)")
        }
        if core.value_order == nil || core.value_order?.isEmpty == true {
            warnings.append("KDNA_Core.json: missing 'value_order' (Judgment governance recommended)")
        }

        // Judgment governance — Patterns extensions (recommended)
        if patterns.aesthetic_preferences == nil || patterns.aesthetic_preferences?.isEmpty == true {
            warnings.append("KDNA_Patterns.json: missing 'aesthetic_preferences' (Judgment governance recommended)")
        }
        if patterns.boundaries == nil || patterns.boundaries?.isEmpty == true {
            warnings.append("KDNA_Patterns.json: missing 'boundaries' (Judgment governance recommended)")
        }
        if let risk = patterns.risk_model {
            if risk.highest_risk_errors == nil || risk.highest_risk_errors?.isEmpty == true {
                warnings.append("KDNA_Patterns.json.risk_model: missing 'highest_risk_errors'")
            }
            if risk.must_block_when == nil || risk.must_block_when?.isEmpty == true {
                warnings.append("KDNA_Patterns.json.risk_model: missing 'must_block_when'")
            }
        } else {
            warnings.append("KDNA_Patterns.json: missing 'risk_model' (Judgment governance recommended)")
        }
        if patterns.counterexamples == nil || patterns.counterexamples?.isEmpty == true {
            warnings.append("KDNA_Patterns.json: missing 'counterexamples' (Judgment governance recommended)")
        }

        // Scenario governance — Scenarios upgrades (recommended)
        if let scenes = domain.scenarios?.scenes {
            for (i, scene) in scenes.enumerated() {
                if scene.trigger_signals == nil || scene.trigger_signals?.isEmpty == true {
                    warnings.append("KDNA_Scenarios.json.scenes[\(i)]: missing 'trigger_signals' (Scenario governance recommended)")
                }
                if scene.negative_signals == nil || scene.negative_signals?.isEmpty == true {
                    warnings.append("KDNA_Scenarios.json.scenes[\(i)]: missing 'negative_signals' (Scenario governance recommended)")
                }
                if scene.classification_rule == nil || scene.classification_rule?.isEmpty == true {
                    warnings.append("KDNA_Scenarios.json.scenes[\(i)]: missing 'classification_rule' (Scenario governance recommended)")
                }
                if scene.risk_level == nil || scene.risk_level?.isEmpty == true {
                    warnings.append("KDNA_Scenarios.json.scenes[\(i)]: missing 'risk_level' (Scenario governance recommended)")
                }
                if scene.expected_judgment_shift == nil || scene.expected_judgment_shift?.isEmpty == true {
                    warnings.append("KDNA_Scenarios.json.scenes[\(i)]: missing 'expected_judgment_shift' (Scenario governance recommended)")
                }
            }
        }

        // Scenario governance — Cases upgrades (recommended)
        if let cases = domain.cases?.cases {
            for (i, c) in cases.enumerated() {
                if c.judgment_path == nil || c.judgment_path?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'judgment_path' (Scenario governance recommended)")
                }
                if c.good_response == nil || c.good_response?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'good_response' (Scenario governance recommended)")
                }
                if c.bad_response == nil || c.bad_response?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'bad_response' (Scenario governance recommended)")
                }
                if c.why_good == nil || c.why_good?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'why_good' (Scenario governance recommended)")
                }
                if c.why_bad == nil || c.why_bad?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'why_bad' (Scenario governance recommended)")
                }
                if c.triggered_axioms == nil || c.triggered_axioms?.isEmpty == true {
                    warnings.append("KDNA_Cases.json.cases[\(i)]: missing 'triggered_axioms' (Scenario governance recommended)")
                }
            }
        }

        return (errors, warnings)
    }

    /// Validate cross-file consistency.
    public static func validateCrossFile(_ domain: KDNADomain) -> (errors: [String], warnings: [String]) {
        var errors: [String] = []
        let warnings: [String] = []

        // Check scenario cross-references in cases
        if let cases = domain.cases?.cases, let scenes = domain.scenarios?.scenes {
            let sceneIds = Set(scenes.compactMap { $0.id })
            for (i, c) in cases.enumerated() {
                if let sceneId = c.scene_id, !sceneIds.contains(sceneId) {
                    errors.append("KDNA_Cases.json.cases[\(i)]: scene_id '\(sceneId)' not found in KDNA_Scenarios.json")
                }
            }
        }

        return (errors, warnings)
    }
}
