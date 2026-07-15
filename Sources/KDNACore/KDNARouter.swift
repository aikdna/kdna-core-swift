//  KDNACore — Domain Router: 7-State routing decision
//  Ported from kdna-cli/src/agent.js cmdRoute()

import Foundation

/// 7-state routing decision output per specs/route-result.schema.json
public struct KDNARouteResult: Codable {
    public var status: KDNARouteStatus
    public var action: KDNARouteAction
    public var needsKdna: Bool
    public var selectedDomain: String?
    public var reason: String
    public var confidence: Double
    public var candidates: [KDNARouteCandidate]
    public var rejectedDomains: [KDNARouteRejection]
    public var trust: KDNATrustResult?
    public var ambiguity: KDNAAmbiguityResult?
    public var registrySuggestions: [KDNARegistrySuggestion]
    public let autoInstall: Bool
    public let traceId: String
    public let createdAt: String
}

public enum KDNARouteStatus: String, Codable {
    case skipNoJudgmentNeeded = "SKIP_NO_JUDGMENT_NEEDED"
    case skipNoLocalDomain = "SKIP_NO_LOCAL_DOMAIN"
    case skipWeakFit = "SKIP_WEAK_FIT"
    case rejectNegativeMatch = "REJECT_NEGATIVE_MATCH"
    case askAmbiguousDomain = "ASK_AMBIGUOUS_DOMAIN"
    case loadStrongFit = "LOAD_STRONG_FIT"
    case blockTrustFailed = "BLOCK_TRUST_FAILED"
}

public enum KDNARouteAction: String, Codable {
    case skip, load, ask, block
}

public struct KDNARouteCandidate: Codable {
    public let domain: String
    public let decision: String  // rejected, weak_match, strong_match, ambiguous
    public let reason: String
    public let confidence: Double
    public let matchedDoesNotApplyWhen: String?
    public let matchedAppliesWhen: String?
}

public struct KDNARouteRejection: Codable {
    public let domain: String
    public let triggeredRule: String
    public let reason: String
}

public struct KDNATrustResult: Codable {
    public let passed: Bool
    public let signatureValid: Bool?
    public let notYanked: Bool
    public let licenseValid: Bool?
    public let failures: [String]
}

public struct KDNAAmbiguityResult: Codable {
    public let domains: [KDNAAmbiguousDomain]
    public let recommendation: String
}

public struct KDNAAmbiguousDomain: Codable {
    public let domain: String
    public let description: String
    public let judgmentFrame: String
    public let riskIfWrong: String
}

public struct KDNARegistrySuggestion: Codable {
    public let domain: String
    public let reason: String
    public let trust: String  // official, community, verified
    public let installCommand: String
}

// MARK: - Router

public class KDNARouter {

    private let domainLoader: KDNADomainLoader
    private let trustVerifier: KDNATrustVerifier?
    private let manifestCache: [String: KDNAManifest]

    public init(domainLoader: KDNADomainLoader = KDNADomainLoader(),
                trustVerifier: KDNATrustVerifier? = nil,
                manifestCache: [String: KDNAManifest] = [:]) {
        self.domainLoader = domainLoader
        self.trustVerifier = trustVerifier
        self.manifestCache = manifestCache
    }

    /// Route a task against installed domains and return a 7-state decision.
    public func route(task: String, installedDomains: [URL], discoverRemote: Bool = false) -> KDNARouteResult {
        let traceId = UUID().uuidString
        var result = KDNARouteResult(
            status: .skipNoJudgmentNeeded,
            action: .skip,
            needsKdna: false,
            selectedDomain: nil,
            reason: "",
            confidence: 0,
            candidates: [],
            rejectedDomains: [],
            trust: nil,
            ambiguity: nil,
            registrySuggestions: [],
            autoInstall: false,
            traceId: traceId,
            createdAt: ISO8601DateFormatter().string(from: Date())
        )

        // ═══ Gate 1: Intent — does this task need domain judgment? ═══
        let judgmentKeywords = ["review","diagnose","critique","evaluate","assess","judge",
                                 "should i","is this good","is this correct","how would you rate"]
        let mechanicalKeywords = ["format","translate","convert","list","find","lookup","search",
                                   "run","execute","compile","build","fix syntax"]
        let taskLower = task.lowercased()
        let hasJudgment = judgmentKeywords.contains(where: taskLower.contains)
        let hasMechanical = mechanicalKeywords.contains(where: taskLower.contains)
        result.needsKdna = hasJudgment && !hasMechanical

        guard result.needsKdna else {
            result.status = .skipNoJudgmentNeeded
            result.action = .skip
            result.reason = hasMechanical ? "task is mechanical" : "task does not need domain judgment"
            return result
        }

        guard !installedDomains.isEmpty else {
            result.status = .skipNoLocalDomain
            result.action = .skip
            result.reason = "no domains installed"
            return result
        }

        // ═══ Gate 2+3: Negative Match First → Domain Fit ═══
        let taskTokens = tokenize(task)
        var candidates: [(domain: String, url: URL, score: Int, reasons: [String], manifest: KDNAManifest?, core: KDNCoreData?)] = []

        for dir in installedDomains {
            guard let manifest = loadManifest(from: dir) else { continue }
            let domainName = manifest.asset_id

            // Yank check
            // (kdna.json yanked field not in current manifest struct — extend if needed)

            // Load core for axiom matching
            guard let core = loadCore(from: dir) else { continue }

            // Negative match: does_not_apply_when
            var disqualified: (axiomId: String, text: String)?
            for axiom in core.axioms ?? [] {
                for exclusion in axiom.does_not_apply_when ?? [] {
                    let score = overlapScore(taskTokens, exclusion)
                    if score >= 2 {
                        disqualified = (axiomId: axiom.id ?? "?", text: exclusion)
                        break
                    }
                }
                if disqualified != nil { break }
            }

            if let dq = disqualified {
                result.rejectedDomains.append(KDNARouteRejection(
                    domain: domainName,
                    triggeredRule: "\(dq.axiomId).does_not_apply_when",
                    reason: dq.text
                ))
                continue
            }

            // Positive fit scoring
            var fitScore = 0
            var fitReasons: [String] = []
            for axiom in core.axioms ?? [] {
                for ap in axiom.applies_when ?? [] {
                    let score = overlapScore(taskTokens, ap)
                    if score >= 2 {
                        fitScore += score * 3
                        fitReasons.append(ap)
                    }
                }
            }

            // Domain relevance from description + keywords
            let descText = [manifest.description, manifest.core_insight].compactMap{$0}.joined(separator: " ")
            let keywordText = (manifest.keywords ?? []).joined(separator: " ")
            let relevanceTokens = tokenize(descText + " " + keywordText)
            let relevanceSet = Set(relevanceTokens)
            fitScore += taskTokens.filter({ relevanceSet.contains($0) }).count * 2

            if fitScore > 0 || !(core.axioms?.isEmpty ?? true) {
                candidates.append((domain: domainName, url: dir, score: fitScore, reasons: fitReasons, manifest: manifest, core: core))
            }
        }

        candidates.sort(by: { $0.score > $1.score })
        let strongCandidates = candidates.filter { $0.score >= 6 }

        // ═══ Gate 4+5: Decision ═══
        if strongCandidates.isEmpty && candidates.isEmpty {
            result.status = .skipNoLocalDomain
            result.action = .skip
            result.reason = "no domain matches this task"
            if !result.rejectedDomains.isEmpty {
                result.reason += " (\(result.rejectedDomains.count) domains excluded by does_not_apply_when)"
            }
        } else if strongCandidates.count == 1 {
            let selected = strongCandidates[0]
            // Trust Gate
            let trust = verifyTrust(domain: selected.domain, url: selected.url)
            result.trust = trust
            if !trust.passed {
                result.status = .blockTrustFailed
                result.action = .block
                result.reason = "trust failed: \(trust.failures.joined(separator: ", "))"
            } else {
                result.status = .loadStrongFit
                result.action = .load
                result.selectedDomain = selected.domain
                result.confidence = min(0.95, 0.5 + Double(selected.score) * 0.05)
                result.reason = "strong match: \(selected.manifest?.description?.prefix(100) ?? "")"
            }
            result.candidates = buildCandidates(strong: [selected], weak: candidates.filter({$0.score < 6}))
        } else if strongCandidates.count > 1 {
            result.status = .askAmbiguousDomain
            result.action = .ask
            result.reason = "\(strongCandidates.count) domains strongly match"
            result.ambiguity = KDNAAmbiguityResult(
                domains: strongCandidates.prefix(3).map { c in
                    KDNAAmbiguousDomain(
                        domain: c.domain,
                        description: c.manifest?.description ?? "",
                        judgmentFrame: c.reasons.first ?? c.manifest?.core_insight ?? "",
                        riskIfWrong: "may misclassify as a \(c.domain.split(separator: "/").last ?? "") problem"
                    )
                },
                recommendation: "Choose the domain whose judgment frame best matches the task intent. Do not blend."
            )
            result.candidates = buildCandidates(strong: strongCandidates, weak: [])
        } else {
            // Only weak candidates
            result.status = .skipWeakFit
            result.action = .skip
            result.reason = "only weak matches found"
            result.candidates = buildCandidates(strong: [], weak: candidates)
        }

        // Add rejections to candidates for full trace
        for rejection in result.rejectedDomains {
            result.candidates.append(KDNARouteCandidate(
                domain: rejection.domain, decision: "rejected",
                reason: rejection.reason, confidence: 0,
                matchedDoesNotApplyWhen: rejection.triggeredRule, matchedAppliesWhen: nil
            ))
        }

        return result
    }

    // MARK: - Helpers

    private func tokenize(_ text: String) -> [String] {
        text.lowercased()
            .components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { $0.count > 2 }
    }

    private func overlapScore(_ taskTokens: [String], _ declaredText: String) -> Int {
        let declaredTokens = tokenize(declaredText)
        let dSet = Set(declaredTokens)
        return taskTokens.filter({ dSet.contains($0) }).count
    }

    private func loadManifest(from dir: URL) -> KDNAManifest? {
        let path = dir.appendingPathComponent("kdna.json")
        guard let data = try? Data(contentsOf: path) else { return nil }
        return try? JSONDecoder().decode(KDNAManifest.self, from: data)
    }

    private func loadCore(from dir: URL) -> KDNCoreData? {
        let path = dir.appendingPathComponent("KDNA_Core.json")
        guard let data = try? Data(contentsOf: path) else { return nil }
        return try? JSONDecoder().decode(KDNCoreData.self, from: data)
    }

    private func verifyTrust(domain: String, url: URL) -> KDNATrustResult {
        if let verifier = trustVerifier {
            return verifier.verify(domainDir: url)
        }
        // Default: trust if exists
        return KDNATrustResult(passed: true, signatureValid: nil, notYanked: true, licenseValid: nil, failures: [])
    }

    private func buildCandidates(strong: [(domain: String, url: URL, score: Int, reasons: [String], manifest: KDNAManifest?, core: KDNCoreData?)],
                                 weak: [(domain: String, url: URL, score: Int, reasons: [String], manifest: KDNAManifest?, core: KDNCoreData?)]) -> [KDNARouteCandidate] {
        var out: [KDNARouteCandidate] = []
        for c in strong {
            out.append(KDNARouteCandidate(domain: c.domain, decision: "strong_match",
                reason: "score \(c.score)", confidence: min(0.95, 0.5 + Double(c.score) * 0.05),
                matchedDoesNotApplyWhen: nil, matchedAppliesWhen: c.reasons.first))
        }
        for c in weak {
            out.append(KDNARouteCandidate(domain: c.domain, decision: "weak_match",
                reason: "score \(c.score)", confidence: 0.15 + Double(c.score) * 0.02,
                matchedDoesNotApplyWhen: nil, matchedAppliesWhen: c.reasons.first))
        }
        return out
    }

    /// Expose available installed domain names for simpler use cases.
    public func availableDomains(from dirs: [URL]) -> [String] {
        dirs.compactMap { loadManifest(from: $0)?.asset_id }
    }

    /// Quick keyword match — lightweight version without full route analysis.
    public func match(task: String, installedDomains: [URL]) -> KDNAMatchResult {
        let taskTokens = tokenize(task)
        var hints: [KDNAMatchHint] = []
        var dropped: [KDNAMatchDrop] = []

        for dir in installedDomains {
            guard let manifest = loadManifest(from: dir),
                  let core = loadCore(from: dir) else { continue }

            // Negative match
            var disqualified: String?
            for axiom in core.axioms ?? [] {
                for exclusion in axiom.does_not_apply_when ?? [] {
                    if overlapScore(taskTokens, exclusion) >= 2 {
                        disqualified = exclusion
                        break
                    }
                }
                if disqualified != nil { break }
            }
            if let dq = disqualified {
                dropped.append(KDNAMatchDrop(domain: manifest.asset_id, reason: dq))
                continue
            }

            // Positive hints
            var score = 0
            for axiom in core.axioms ?? [] {
                for ap in axiom.applies_when ?? [] {
                    let s = overlapScore(taskTokens, ap)
                    if s >= 2 { score += s }
                }
            }
            let descText = [manifest.description, manifest.core_insight].compactMap{$0}.joined(separator: " ")
            score += overlapScore(taskTokens, descText)

            if score > 0 {
                hints.append(KDNAMatchHint(domain: manifest.asset_id, score: score, description: manifest.description ?? ""))
            }
        }

        hints.sort(by: { $0.score > $1.score })
        return KDNAMatchResult(task: task, hints: hints, dropped: dropped)
    }
}

public struct KDNAMatchResult: Codable {
    public let task: String
    public let hints: [KDNAMatchHint]
    public let dropped: [KDNAMatchDrop]
}

public struct KDNAMatchHint: Codable {
    public let domain: String
    public let score: Int
    public let description: String
}

public struct KDNAMatchDrop: Codable {
    public let domain: String
    public let reason: String
}
