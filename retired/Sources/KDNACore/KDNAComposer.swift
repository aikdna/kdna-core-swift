//  KDNACore — Composer: multi-domain loading with conflict detection

import Foundation

/// Result of composing multiple KDNA domains for a single task.
public struct KDNAComposeResult {
    public let domains: [String]
    public let primary: KDNADomain
    public let constraints: [KDNADomain]  // Secondary domains acting as constraints (e.g. agent_safety)
    public let conflicts: [KDNADomainConflict]
    public let combinedContext: String
    public let warnings: [String]
}

/// A conflict between two domains loaded simultaneously.
public struct KDNADomainConflict {
    public let domainA: String
    public let domainB: String
    public let conflictType: KDNAConflictType
    public let description: String
}

public enum KDNAConflictType: String {
    case stanceConflict    // Stances directly contradict
    case scopeConflict     // Domain scopes overlap with different judgment frames
    case termConflict      // One domain bans a term another domain uses
    case axiomConflict     // Axioms cannot both be true
}

/// Composer for multi-domain KDNA loading.
public class KDNAComposer {

    private let loader: KDNADomainLoader

    public init(loader: KDNADomainLoader = KDNADomainLoader()) {
        self.loader = loader
    }

    /// Compose multiple domains into a single context, detecting conflicts.
    /// - Parameters:
    ///   - primaryDomain: The main domain to apply (from route result)
    ///   - secondaryDomains: Constraint domains (e.g. agent_safety) that always apply
    /// - Returns: Composed result with combined context and conflict report
    public func compose(primary: KDNADomain, secondaries: [KDNADomain] = [], input: String = "") -> KDNAComposeResult {
        var conflicts: [KDNADomainConflict] = []
        var warnings: [String] = []
        let primaryName = primary.core.meta.domain
        let secondaryNames = secondaries.map { $0.core.meta.domain }
        var contextParts: [String] = []

        // Primary domain context
        let primaryCtx = KDNADomainLoader.formatContext(primary)
        contextParts.append("## Primary Domain: \(primaryName)\n\(primaryCtx)")

        // Constraint domains with conflict detection
        for secondary in secondaries {
            let secName = secondary.core.meta.domain

            // Detect stance conflicts
            if let primaryStances = primary.core.stances, let secStances = secondary.core.stances {
                for ps in primaryStances {
                    for ss in secStances {
                        if stanceConflicts(ps.stance, ss.stance) {
                            conflicts.append(KDNADomainConflict(
                                domainA: primaryName, domainB: secName,
                                conflictType: .stanceConflict,
                                description: "Stance conflict: '\(ps.stance)' vs '\(ss.stance)'"
                            ))
                        }
                    }
                }
            }

            // Detect banned term conflicts
            if let primaryBanned = primary.patterns.terminology?.banned_terms,
               let secStances = secondary.core.stances {
                let bannedTerms = Set(primaryBanned.map { $0.term.lowercased() })
                for stance in secStances {
                    let words = stance.stance.lowercased().split(separator: " ").map(String.init)
                    if words.contains(where: { bannedTerms.contains($0) }) {
                        conflicts.append(KDNADomainConflict(
                            domainA: primaryName, domainB: secName,
                            conflictType: .termConflict,
                            description: "\(primaryName) bans a term used in \(secName)'s stance '\(stance.stance)'"
                        ))
                    }
                }
            }

            // Detect axiom conflicts (simple keyword opposition check)
            if let primaryAxioms = primary.core.axioms, let secAxioms = secondary.core.axioms {
                for pa in primaryAxioms {
                    for sa in secAxioms {
                        if axiomConflicts(pa.one_sentence, sa.one_sentence) {
                            conflicts.append(KDNADomainConflict(
                                domainA: primaryName, domainB: secName,
                                conflictType: .axiomConflict,
                                description: "Potential conflict: '\(pa.one_sentence)' vs '\(sa.one_sentence)'"
                            ))
                        }
                    }
                }
            }

            let secCtx = KDNADomainLoader.formatContext(secondary)
            contextParts.append("## Constraint Domain: \(secName) (applied as boundary)\n\(secCtx)")
        }

        if !conflicts.isEmpty {
            warnings.append("\(conflicts.count) domain conflict(s) detected. Primary domain \(primaryName) takes precedence.")
            for c in conflicts {
                warnings.append("  ⚠ \(c.description)")
            }
        }

        if secondaries.count > 2 {
            warnings.append("\(secondaries.count + 1) domains loaded — consider narrowing to reduce judgment dilution.")
        }

        let combined = contextParts.joined(separator: "\n\n---\n\n")

        return KDNAComposeResult(
            domains: [primaryName] + secondaryNames,
            primary: primary,
            constraints: secondaries,
            conflicts: conflicts,
            combinedContext: combined,
            warnings: warnings
        )
    }

    // MARK: - Conflict Detection Helpers

    private func stanceConflicts(_ a: String, _ b: String) -> Bool {
        let al = a.lowercased(), bl = b.lowercased()
        let oppositionPairs: [(String, String)] = [
            ("must", "should not"), ("always", "never"), ("required", "optional"),
            ("prioritize", "avoid"), ("embrace", "reject")
        ]
        for (pos, neg) in oppositionPairs {
            if (al.contains(pos) && bl.contains(neg)) || (al.contains(neg) && bl.contains(pos)) {
                return true
            }
        }
        return false
    }

    private func axiomConflicts(_ a: String, _ b: String) -> Bool {
        // Simple heuristic: if two axioms use strongly opposing language
        let al = a.lowercased(), bl = b.lowercased()
        let oppositionWords = ["never", "always", "must not", "cannot", "should not"]
        let hasOppositionA = oppositionWords.contains(where: al.contains)
        let hasOppositionB = oppositionWords.contains(where: bl.contains)
        // Only flag if both use strong absolute language in potentially opposing ways
        return hasOppositionA && hasOppositionB && al != bl
    }
}
