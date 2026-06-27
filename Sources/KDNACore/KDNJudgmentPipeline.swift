//  KDNACore — Swift implementation of the KDNA Protocol v0.7
//  (file history: previously labeled "v1.0-rc"; the v0.7 launch 2026-05-22
//   superseded that label. See CHANGELOG.md for the version timeline.)
//  https://github.com/aikdna/kdna

import Foundation

/// The judgment pipeline: preFilter → systemPrompt injection → postValidate.
/// This is the core differentiator of KDNA-enabled clients from ordinary chat apps.
public class KDNJudgmentPipeline {

    public init() {}

    private let domainLoader = KDNADomainLoader.self

    // MARK: - Pre-Filter

    /// Run preFilter on user input against loaded domains.
    /// Detects banned terms, scenario signals, and misunderstandings.
    public func preFilter(input: String, domains: [KDNADomain]) -> KDNAPreFilterResult {
        var bannedTerms: [BannedTermMatch] = []
        var signals: [String] = []

        for domain in domains {
            let domainName = domain.core.meta.domain

            // Check banned terms
            if let bannedList = domain.patterns.terminology?.banned_terms {
                for bannedTerm in bannedList {
                    if input.lowercased().contains(bannedTerm.term.lowercased()) {
                        bannedTerms.append(BannedTermMatch(
                            term: bannedTerm.term,
                            replaceWith: bannedTerm.replace_with,
                            why: bannedTerm.why,
                            sourceDomain: domainName
                        ))
                    }
                }
            }

            // Check scenario signals
            if let scenes = domain.scenarios?.scenes {
                for scene in scenes {
                    let matched = scene.trigger_signals?.contains { input.lowercased().contains($0.lowercased()) } ?? false
                    if matched {
                        signals.append("\(domainName):\(scene.name)")
                    }
                }
            }
        }

        return KDNAPreFilterResult(
            shouldBlock: false,
            blockReason: nil,
            bannedTerms: bannedTerms,
            signals: signals
        )
    }

    // MARK: - Build System Message

    /// Build a system message that injects KDNA domain context before base instructions.
    public func buildSystemMessage(
        domain: KDNADomain?,
        baseSystemMessage: String,
        projectContext: String?,
        strategy: KDNASystemPromptStrategy = .domainFirst
    ) -> String {
        let kdnaSections = buildKDNASections(domain: domain, domains: nil, strategy: strategy)
        return assembleSystemMessage(
            kdnaSections: kdnaSections,
            baseSystemMessage: baseSystemMessage,
            projectContext: projectContext,
            strategy: strategy
        )
    }

    /// Build a system message that injects multiple KDNA domain contexts.
    public func buildSystemMessage(
        domains: [KDNADomain],
        baseSystemMessage: String,
        projectContext: String?,
        strategy: KDNASystemPromptStrategy = .domainFirst
    ) -> String {
        let kdnaSections = buildKDNASections(domain: nil, domains: domains, strategy: strategy)
        return assembleSystemMessage(
            kdnaSections: kdnaSections,
            baseSystemMessage: baseSystemMessage,
            projectContext: projectContext,
            strategy: strategy
        )
    }

    // MARK: - System Message Assembly

    private func buildKDNASections(
        domain: KDNADomain?,
        domains: [KDNADomain]?,
        strategy: KDNASystemPromptStrategy
    ) -> [String] {
        var sections: [String] = []

        let hasDomains = domain != nil || (domains?.isEmpty == false)
        guard hasDomains else { return sections }

        // Domain Cognition
        let cognitionContext: String
        if strategy == .compactDomain {
            if let d = domain {
                cognitionContext = formatCompactContext(d)
            } else if let ds = domains {
                cognitionContext = ds.map { formatCompactContext($0) }.joined(separator: "\n\n---\n\n")
            } else {
                cognitionContext = ""
            }
        } else {
            if let d = domain {
                cognitionContext = KDNADomainLoader.formatContext(d)
            } else if let ds = domains {
                cognitionContext = KDNACompose.composeContext(domains: ds)
            } else {
                cognitionContext = ""
            }
        }

        if !cognitionContext.isEmpty {
            sections.append("""
            === KDNA DOMAIN COGNITION ===
            \(cognitionContext)
            =============================
            """)
        }

        // Judgment Instructions
        let instructions = strategy == .strictJudgment ? strictJudgmentInstructions : standardJudgmentInstructions
        sections.append(instructions)

        return sections
    }

    private func assembleSystemMessage(
        kdnaSections: [String],
        baseSystemMessage: String,
        projectContext: String?,
        strategy: KDNASystemPromptStrategy
    ) -> String {
        var sections: [String] = []

        let baseSection = baseSystemMessage.isEmpty ? nil : """
        === BASE INSTRUCTIONS ===
        \(baseSystemMessage)
        ========================
        """

        switch strategy {
        case .personaFirst:
            if let base = baseSection { sections.append(base) }
            sections.append(contentsOf: kdnaSections)
        default:
            // domainFirst, compactDomain, strictJudgment
            sections.append(contentsOf: kdnaSections)
            if let base = baseSection { sections.append(base) }
        }

        if let projectContext = projectContext, !projectContext.isEmpty {
            sections.append("""
            === PROJECT CONTEXT ===
            \(projectContext)
            =======================
            """)
        }

        return sections.joined(separator: "\n")
    }

    private var standardJudgmentInstructions: String {
        """
        === KDNA JUDGMENT INSTRUCTIONS ===
        When analyzing any input:
         1. Classify the situation against the domain cognition above
         2. Check common misunderstandings
         3. Apply the relevant framework
         4. Run self-checks before finalizing
         5. State your classification explicitly
         6. Flag banned terms in input or output
        Be concise. Focus on judgment.
        =================================
        """
    }

    private var strictJudgmentInstructions: String {
        """
        === KDNA JUDGMENT INSTRUCTIONS (STRICT) ===
        Before generating ANY response:
         1. CLASSIFY the user's situation against the domain cognition
         2. IDENTIFY which axioms are relevant and cite them
         3. CHECK every common misunderstanding listed — state if any apply
         4. SELECT the most appropriate framework and follow its steps
         5. VERIFY you have not used any banned terms — replace if found
         6. RUN all self-checks and confirm each passes
         7. STATE your classification explicitly in the output
         8. FLAG any banned terms detected in input or output
         9. EXPLAIN your reasoning chain for non-obvious conclusions
        10. RESPECT the value order — when values conflict, prioritize according to the domain's stated order
        11. HONOR boundaries — do not cross any must_not_do rules unless an acceptable exception is listed
        12. EVALUATE risk — consider the highest_risk_errors and must_block_when conditions before acting
        You MUST show your judgment work. Do not skip steps.
        ==========================================
        """
    }

    private func formatCompactContext(_ domain: KDNADomain) -> String {
        var parts: [String] = []
        parts.append("Domain: \(domain.core.meta.domain)")

        if let hq = domain.core.highest_question, !hq.isEmpty {
            parts.append("Q: \(hq)")
        }

        if let worldview = domain.core.worldview, !worldview.isEmpty {
            parts.append("Worldview: \(worldview.joined(separator: "; "))")
        }

        if let valueOrder = domain.core.value_order, !valueOrder.isEmpty {
            parts.append("Values: \(valueOrder.joined(separator: " > "))")
        }

        if let axioms = domain.core.axioms, !axioms.isEmpty {
            parts.append("Axioms:")
            for axiom in axioms {
                parts.append("- \(axiom.one_sentence)")
            }
        }

        if let selfChecks = domain.patterns.self_check, !selfChecks.isEmpty {
            parts.append("Self-Checks:")
            for check in selfChecks {
                parts.append("- [ ] \(check)")
            }
        }

        if let banned = domain.patterns.terminology?.banned_terms, !banned.isEmpty {
            parts.append("Banned: \(banned.map { $0.term }.joined(separator: ", "))")
        }

        if let risk = domain.patterns.risk_model {
            if let highest = risk.highest_risk_errors, !highest.isEmpty {
                parts.append("Risk: \(highest.joined(separator: "; "))")
            }
        }

        return parts.joined(separator: "\n")
    }

    // MARK: - Post-Validate

    /// Run postValidate on LLM response against loaded domains.
    public func postValidate(response: String, domains: [KDNADomain]) -> KDNAPostValidateResult {
        var bannedTerms: [BannedTermMatch] = []
        var selfChecksFailed: [String] = []
        var misunderstandingsDetected: [String] = []

        for domain in domains {
            let domainName = domain.core.meta.domain

            // Check banned terms in response
            if let bannedList = domain.patterns.terminology?.banned_terms {
                for bannedTerm in bannedList {
                    if response.lowercased().contains(bannedTerm.term.lowercased()) {
                        bannedTerms.append(BannedTermMatch(
                            term: bannedTerm.term,
                            replaceWith: bannedTerm.replace_with,
                            why: bannedTerm.why,
                            sourceDomain: domainName
                        ))
                    }
                }
            }

            // Check self_checks — look for response patterns that address each check
            if let selfChecks = domain.patterns.self_check {
                for check in selfChecks {
                    let checkKeywords = check.lowercased()
                        .replacingOccurrences(of: "[", with: "")
                        .replacingOccurrences(of: "]", with: "")
                        .split(separator: " ")
                        .map(String.init)

                    let matched = checkKeywords.contains { keyword in
                        response.lowercased().contains(keyword)
                    }

                    if !matched {
                        selfChecksFailed.append("[\(domainName)] \(check)")
                    }
                }
            }

            // Check misunderstandings
            if let misunderstandings = domain.patterns.misunderstandings {
                for misunderstanding in misunderstandings {
                    if response.lowercased().contains(misunderstanding.wrong.lowercased()) {
                        misunderstandingsDetected.append("[\(domainName)] \(misunderstanding.wrong)")
                    }
                }
            }
        }

        let passed = bannedTerms.isEmpty && selfChecksFailed.count <= (domains.first?.patterns.self_check?.count ?? 1) / 2

        return KDNAPostValidateResult(
            passed: passed,
            bannedTerms: bannedTerms,
            selfChecksFailed: selfChecksFailed,
            misunderstandings: misunderstandingsDetected
        )
    }
}

// MARK: - Multi-Domain Composition

/// Composes judgment constraints from multiple KDNA domains into a single agent context.
/// Domains contribute independently; conflicts are surfaced, not silently resolved.
public class KDNACompose {

    public static func composeContext(domains: [KDNADomain], separator: String = "\n\n---\n\n") -> String {
        let validDomains = domains
        let contexts = validDomains.map { KDNADomainLoader.formatContext($0) }.filter { !$0.isEmpty }
        return contexts.joined(separator: separator)
    }

    public static func classifySignals(input: String, domains: [KDNADomain]) -> [String] {
        let lower = input.lowercased()
        var matchedDomainIds: [String] = []
        for domain in domains {
            let domainName = domain.core.meta.domain
            let signals = domain.core.trigger_signals ?? []
            if signals.isEmpty {
                matchedDomainIds.append(domainName)
                continue
            }
            let hasMatch = signals.contains { lower.contains($0.lowercased()) }
            if hasMatch { matchedDomainIds.append(domainName) }
        }
        return Array(Set(matchedDomainIds))
    }

    public static func composeChecks(domains: [KDNADomain]) -> [String] {
        var checks: [String] = []
        for domain in domains {
            let name = domain.core.meta.domain
            let items = domain.patterns.self_check ?? []
            guard !items.isEmpty else { continue }
            if domains.count == 1 {
                checks.append(contentsOf: items)
            } else {
                for item in items { checks.append("[\(name)] \(item)") }
            }
        }
        return checks
    }

    public static func detectConflicts(domains: [KDNADomain]) -> [String] {
        guard domains.count > 1 else { return [] }
        var conflicts: [String] = []
        for i in 0..<domains.count {
            for j in (i + 1)..<domains.count {
                let d1 = domains[i], d2 = domains[j]
                let name1 = d1.core.meta.domain, name2 = d2.core.meta.domain
                let banned1 = d1.patterns.terminology?.banned_terms?.map { $0.term.lowercased() } ?? []
                let banned2 = d2.patterns.terminology?.banned_terms?.map { $0.term.lowercased() } ?? []
                if let std2 = d2.patterns.terminology?.standard_terms {
                    for term in std2 {
                        if banned1.contains(term.term.lowercased()) {
                            conflicts.append("[\(name1)] bans '\(term.term)' but [\(name2)] uses it as a standard term.")
                        }
                    }
                }
                if let std1 = d1.patterns.terminology?.standard_terms {
                    for term in std1 {
                        if banned2.contains(term.term.lowercased()) {
                            conflicts.append("[\(name2)] bans '\(term.term)' but [\(name1)] uses it as a standard term.")
                        }
                    }
                }
                let stances1 = d1.core.stances ?? []
                let stances2 = d2.core.stances ?? []
                for s1 in stances1 {
                    for s2 in stances2 {
                        if areStancesConflicting(s1.stance, s2.stance) {
                            conflicts.append("[\(name1)] stance '\(s1.stance)' may conflict with [\(name2)] stance '\(s2.stance)'.")
                        }
                    }
                }
            }
        }
        return conflicts
    }

    private static func areStancesConflicting(_ s1: String, _ s2: String) -> Bool {
        let lower1 = s1.lowercased(), lower2 = s2.lowercased()
        let opposites = [("always", "never"), ("must", "must not"), ("should", "should not"),
                         ("reject", "accept"), ("avoid", "prefer"), ("minimize", "maximize"),
                         ("silent", "verbose"), ("strict", "lenient")]
        for (a, b) in opposites {
            if (lower1.contains(a) && lower2.contains(b)) || (lower1.contains(b) && lower2.contains(a)) {
                return true
            }
        }
        return false
    }
}
