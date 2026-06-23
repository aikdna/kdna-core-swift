//  KDNACore — Swift implementation of the KDNA Protocol v1.0-rc
//  https://github.com/aikdna/kdna

import Foundation

enum KDNAPlatformPaths {
    static var kdnaDirectory: URL {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        let baseDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return baseDirectory.appendingPathComponent("KDNA", isDirectory: true)
        #else
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".kdna", isDirectory: true)
        #endif
    }

    static var packagesDirectory: URL {
        kdnaDirectory.appendingPathComponent("packages", isDirectory: true)
    }

    static var packageIndexFile: URL {
        kdnaDirectory.appendingPathComponent("index.json")
    }

    static var licensesDirectory: URL {
        kdnaDirectory.appendingPathComponent("licenses", isDirectory: true)
    }
}

/// Swift native port of @aikdna/kdna-core loader.js
/// Loads KDNA domain cognition from parsed JSON files.
public class KDNADomainLoader {

    public init() {}

    public static let fileMap: [String: String] = [
        "core": "KDNA_Core.json",
        "patterns": "KDNA_Patterns.json",
        "scenarios": "KDNA_Scenarios.json",
        "cases": "KDNA_Cases.json",
        "reasoning": "KDNA_Reasoning.json",
        "evolution": "KDNA_Evolution.json",
    ]

    /// Load a complete KDNA domain from a map of parsed data.
    public static func loadDomain(dataMap: [String: Codable], input: String = "", mode: String = "auto") -> KDNADomain? {
        guard let coreData = dataMap["core"] as? KDNCoreData,
              let patternsData = dataMap["patterns"] as? KDNAPatternsData else {
            return nil
        }

        let base = KDNADomain(
            core: coreData,
            patterns: patternsData,
            scenarios: nil,
            cases: nil,
            reasoning: nil,
            evolution: nil
        )

        if mode == "minimum" { return base }

        let toLoad: [String]
        if mode == "all" {
            toLoad = ["scenarios", "cases", "reasoning", "evolution"]
        } else {
            toLoad = classifyInput(input)
        }

        var domain = base
        for key in toLoad {
            switch key {
            case "scenarios": domain.scenarios = dataMap["scenarios"] as? KDNAScenariosData
            case "cases": domain.cases = dataMap["cases"] as? KDNACasesData
            case "reasoning": domain.reasoning = dataMap["reasoning"] as? KDNAReasoningData
            case "evolution": domain.evolution = dataMap["evolution"] as? KDNAEvolutionData
            default: break
            }
        }

        return domain
    }

    /// Load domain from a dev source directory.
    public static func load(path: String, input: String = "", mode: String = "auto") -> KDNADomain? {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: path) else { return nil }

        var dataMap: [String: Codable] = [:]

        // Load KDNA_Core.json and KDNA_Patterns.json (required)
        if let core = loadJSON(type: KDNCoreData.self, basePath: path, filename: "KDNA_Core.json") {
            dataMap["core"] = core
        } else {
            return nil
        }

        if let patterns = loadJSON(type: KDNAPatternsData.self, basePath: path, filename: "KDNA_Patterns.json") {
            dataMap["patterns"] = patterns
        } else {
            return nil
        }

        // Load optional files
        if let scenarios = loadJSON(type: KDNAScenariosData.self, basePath: path, filename: "KDNA_Scenarios.json") {
            dataMap["scenarios"] = scenarios
        }
        if let cases = loadJSON(type: KDNACasesData.self, basePath: path, filename: "KDNA_Cases.json") {
            dataMap["cases"] = cases
        }
        if let reasoning = loadJSON(type: KDNAReasoningData.self, basePath: path, filename: "KDNA_Reasoning.json") {
            dataMap["reasoning"] = reasoning
        }
        if let evolution = loadJSON(type: KDNAEvolutionData.self, basePath: path, filename: "KDNA_Evolution.json") {
            dataMap["evolution"] = evolution
        }

        return loadDomain(dataMap: dataMap, input: input, mode: mode)
    }

    /// Load domain directly from a `.kdna` file without persistent extraction.
    /// For protected assets, provide the password to decrypt entries in memory.
    public static func load(fromKDNA path: String, password: String? = nil, input: String = "", mode: String = "auto") -> KDNADomain? {
        let reader = KDNAAssetReader()
        guard let asset = try? reader.open(path: path),
              let manifest = try? reader.decodeManifest(asset: asset) else {
            return nil
        }

        let isProtected = manifest.access == "protected"
        let decryptEntry: KDNADecryptEntry? = {
            guard isProtected, let password = password else { return nil }
            return createPasswordDecryptEntry(password: password)
        }()

        var dataMap: [String: Codable] = [:]

        guard let coreData: KDNCoreData = loadEntry(reader: reader, asset: asset, name: "KDNA_Core.json", manifest: manifest, decryptEntry: decryptEntry) else {
            return nil
        }
        dataMap["core"] = coreData

        guard let patternsData: KDNAPatternsData = loadEntry(reader: reader, asset: asset, name: "KDNA_Patterns.json", manifest: manifest, decryptEntry: decryptEntry) else {
            return nil
        }
        dataMap["patterns"] = patternsData

        if let scenarios: KDNAScenariosData = loadEntry(reader: reader, asset: asset, name: "KDNA_Scenarios.json", manifest: manifest, decryptEntry: decryptEntry) {
            dataMap["scenarios"] = scenarios
        }
        if let cases: KDNACasesData = loadEntry(reader: reader, asset: asset, name: "KDNA_Cases.json", manifest: manifest, decryptEntry: decryptEntry) {
            dataMap["cases"] = cases
        }
        if let reasoning: KDNAReasoningData = loadEntry(reader: reader, asset: asset, name: "KDNA_Reasoning.json", manifest: manifest, decryptEntry: decryptEntry) {
            dataMap["reasoning"] = reasoning
        }
        if let evolution: KDNAEvolutionData = loadEntry(reader: reader, asset: asset, name: "KDNA_Evolution.json", manifest: manifest, decryptEntry: decryptEntry) {
            dataMap["evolution"] = evolution
        }

        return loadDomain(dataMap: dataMap, input: input, mode: mode)
    }

    private static func loadEntry<T: Codable>(reader: KDNAAssetReader, asset: KDNAAsset, name: String, manifest: KDNAManifest, decryptEntry: KDNADecryptEntry?) -> T? {
        guard let data = try? reader.readEntry(asset: asset, name: name, manifest: manifest, decryptEntry: decryptEntry),
              let value = try? JSONDecoder().decode(T.self, from: data) else {
            return nil
        }
        return value
    }

    /// Read installed .kdna asset paths from ~/.kdna/index.json.
    public static func scanInstalledAssetPaths() -> [String: String] {
        guard let data = try? Data(contentsOf: KDNAPlatformPaths.packageIndexFile),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let packages = object["packages"] as? [String: Any] else {
            return [:]
        }

        var assets: [String: String] = [:]
        for (name, value) in packages {
            guard let entry = value as? [String: Any],
                  let assetPath = entry["asset_path"] as? String else { continue }
            assets[name] = assetPath
        }
        return assets
    }

    /// Scan installed .kdna assets and load each as a KDNADomain.
    public static func scanInstalledDomains() -> [String: KDNADomain] {
        var domains: [String: KDNADomain] = [:]
        let paths = scanInstalledAssetPaths()
        for (name, assetPath) in paths {
            if let domain = load(fromKDNA: assetPath) {
                domains[name] = domain
            }
        }
        return domains
    }

    /// Scan a dev workspace directory for KDNA domain source subdirectories.
    public static func scanDomains(at path: String) -> [String: KDNADomain] {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: path) else { return [:] }

        var domains: [String: KDNADomain] = [:]
        guard let items = try? fileManager.contentsOfDirectory(atPath: path) else { return [:] }

        for item in items {
            let domainPath = (path as NSString).appendingPathComponent(item)
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: domainPath, isDirectory: &isDir), isDir.boolValue else { continue }

            if let domain = load(path: domainPath) {
                domains[item] = domain
            }
        }

        return domains
    }

    // MARK: - Format Context

    /// Format a loaded KDNA domain into a context string for system prompt injection.
    public static func formatContext(_ domain: KDNADomain) -> String {
        var parts: [String] = []

        parts.append("## Domain Cognition (KDNA)")
        parts.append("Domain: \(domain.core.meta.domain)")
        parts.append("")

        // Highest Question
        if let hq = domain.core.highest_question, !hq.isEmpty {
            parts.append("### Highest Question")
            parts.append("\(hq)")
            parts.append("")
        }

        // Worldview
        if let worldview = domain.core.worldview, !worldview.isEmpty {
            parts.append("### Worldview")
            for belief in worldview {
                parts.append("- \(belief)")
            }
            parts.append("")
        }

        // Judgment Role
        if let role = domain.core.judgment_role {
            parts.append("### Judgment Role")
            parts.append("- Acts as: \(role.acts_as)")
            parts.append("- Does not act as: \(role.does_not_act_as)")
            parts.append("- Responsibility: \(role.responsibility)")
            parts.append("")
        }

        // Value Order
        if let valueOrder = domain.core.value_order, !valueOrder.isEmpty {
            parts.append("### Value Order")
            for (i, value) in valueOrder.enumerated() {
                parts.append("\(i + 1). \(value)")
            }
            parts.append("")
        }

        // Stances
        if let stances = domain.core.stances, !stances.isEmpty {
            parts.append("### Stances")
            for stance in stances {
                parts.append("- \(stance.stance)")
                if let applies = stance.applies_when, !applies.isEmpty {
                    parts.append("  *Applies when:* \(applies.joined(separator: ", "))")
                }
                if let notApplies = stance.does_not_apply_when, !notApplies.isEmpty {
                    parts.append("  *Does not apply when:* \(notApplies.joined(separator: ", "))")
                }
            }
            parts.append("")
        }

        // Axioms
        if let axioms = domain.core.axioms, !axioms.isEmpty {
            parts.append("### Axioms")
            for axiom in axioms {
                parts.append("- **\(axiom.one_sentence)** \(axiom.full_statement)")
                parts.append("  *Why:* \(axiom.why)")
            }
            parts.append("")
        }

        // Key Concepts
        if let ontology = domain.core.ontology, !ontology.isEmpty {
            parts.append("### Key Concepts")
            for concept in ontology {
                parts.append("- **\(concept.id?.replacingOccurrences(of: "_", with: " ") ?? "")** — \(concept.one_sentence)")
                parts.append("  Boundary: \(concept.boundary)")
            }
            parts.append("")
        }

        // Frameworks
        if let frameworks = domain.core.frameworks, !frameworks.isEmpty {
            parts.append("### Frameworks")
            for framework in frameworks {
                parts.append("- **\(framework.name)**: \(framework.when_to_use ?? "Use when this framework matches the user's situation.")")
            }
            parts.append("")
        }

        // Banned Terms
        if let bannedTerms = domain.patterns.terminology?.banned_terms, !bannedTerms.isEmpty {
            parts.append("### Avoid These Terms")
            for term in bannedTerms {
                parts.append("- Avoid \"\(term.term)\". \(term.why) Use \"\(term.replace_with)\" instead.")
            }
            parts.append("")
        }

        // Aesthetic Preferences
        if let aesthetics = domain.patterns.aesthetic_preferences, !aesthetics.isEmpty {
            parts.append("### Aesthetic Preferences")
            for a in aesthetics {
                parts.append("- **Prefer:** \(a.prefer)")
                parts.append("  **Avoid:** \(a.avoid)")
                if let good = a.signals_good, !good.isEmpty {
                    parts.append("  *Signals good:* \(good.joined(separator: ", "))")
                }
                if let bad = a.signals_bad, !bad.isEmpty {
                    parts.append("  *Signals bad:* \(bad.joined(separator: ", "))")
                }
            }
            parts.append("")
        }

        // Boundaries
        if let boundaries = domain.patterns.boundaries, !boundaries.isEmpty {
            parts.append("### Boundaries")
            for b in boundaries {
                parts.append("- **Rule:** \(b.rule)")
                parts.append("  *Why:* \(b.why)")
                parts.append("  *Must not do:* \(b.must_not_do)")
                if let exception = b.acceptable_exception, !exception.isEmpty {
                    parts.append("  *Acceptable exception:* \(exception)")
                }
            }
            parts.append("")
        }

        // Risk Model
        if let risk = domain.patterns.risk_model {
            parts.append("### Risk Model")
            if let highest = risk.highest_risk_errors, !highest.isEmpty {
                parts.append("- **Highest risk errors:** \(highest.joined(separator: "; "))")
            }
            if let acceptable = risk.acceptable_errors, !acceptable.isEmpty {
                parts.append("- **Acceptable errors:** \(acceptable.joined(separator: "; "))")
            }
            if let block = risk.must_block_when, !block.isEmpty {
                parts.append("- **Must block when:** \(block)")
            }
            if let warn = risk.warn_when, !warn.isEmpty {
                parts.append("- **Warn when:** \(warn)")
            }
            parts.append("")
        }

        // Misunderstandings
        if let misunderstandings = domain.patterns.misunderstandings, !misunderstandings.isEmpty {
            parts.append("### Watch For These Misunderstandings")
            for m in misunderstandings {
                parts.append("- **Wrong:** \(m.wrong)")
                parts.append("  **Correct:** \(m.correct)")
            }
            parts.append("")
        }

        // Self Checks
        if let selfChecks = domain.patterns.self_check, !selfChecks.isEmpty {
            parts.append("### Before Responding, Check")
            for check in selfChecks {
                parts.append("- [ ] \(check)")
            }
            parts.append("")
        }

        // Counterexamples
        if let counterexamples = domain.patterns.counterexamples, !counterexamples.isEmpty {
            parts.append("### Counterexamples")
            for c in counterexamples {
                parts.append("- **Bad example:** \(c.bad_example)")
                parts.append("  *Why bad:* \(c.why_bad)")
                if let violated = c.violated_axioms, !violated.isEmpty {
                    parts.append("  *Violated axioms:* \(violated.joined(separator: ", "))")
                }
                parts.append("  *Better direction:* \(c.better_direction)")
            }
            parts.append("")
        }

        // Scenarios
        if let scenes = domain.scenarios?.scenes, !scenes.isEmpty {
            parts.append("### Relevant Scenarios")
            for scene in scenes {
                parts.append("- **\(scene.name)**")
                if let signals = scene.trigger_signals, !signals.isEmpty {
                    parts.append("  *Trigger signals:* \(signals.joined(separator: "; "))")
                }
                if let negative = scene.negative_signals, !negative.isEmpty {
                    parts.append("  *Negative signals:* \(negative.joined(separator: "; "))")
                }
                if let rule = scene.classification_rule, !rule.isEmpty {
                    parts.append("  *Classification rule:* \(rule)")
                }
                if let risk = scene.risk_level, !risk.isEmpty {
                    parts.append("  *Risk level:* \(risk)")
                }
                if let shift = scene.expected_judgment_shift, !shift.isEmpty {
                    parts.append("  *Expected judgment shift:* \(shift)")
                }
            }
            parts.append("")
        }

        // Reasoning Chains
        if let chains = domain.reasoning?.reasoning_chains, !chains.isEmpty {
            parts.append("### Reasoning Chains")
            for chain in chains {
                parts.append("- **\(chain.one_sentence)** → \(chain.so_what)")
            }
            parts.append("")
        }

        // Cases
        if let cases = domain.cases?.cases, !cases.isEmpty {
            parts.append("### Cases")
            for c in cases {
                parts.append("- **\(c.title)**")
                parts.append("  Context: \(c.context)")
                parts.append("  What happened: \(c.what_happened)")
                parts.append("  Learned: \(c.what_was_learned)")
                parts.append("  Pattern: \(c.structural_pattern)")
                if let path = c.judgment_path, !path.isEmpty {
                    parts.append("  *Judgment path:* \(path)")
                }
                if let good = c.good_response, !good.isEmpty {
                    parts.append("  *Good response:* \(good)")
                }
                if let bad = c.bad_response, !bad.isEmpty {
                    parts.append("  *Bad response:* \(bad)")
                }
                if let whyGood = c.why_good, !whyGood.isEmpty {
                    parts.append("  *Why good:* \(whyGood)")
                }
                if let whyBad = c.why_bad, !whyBad.isEmpty {
                    parts.append("  *Why bad:* \(whyBad)")
                }
                if let triggered = c.triggered_axioms, !triggered.isEmpty {
                    parts.append("  *Triggered axioms:* \(triggered.joined(separator: ", "))")
                }
            }
            parts.append("")
        }

        // Evolution
        if let evolution = domain.evolution {
            if let stages = evolution.stages, !stages.isEmpty {
                parts.append("### Growth Stages")
                for stage in stages {
                    parts.append("- **\(stage.name)**: \(stage.description)")
                }
                parts.append("")
            }
            if let layers = evolution.evolution_layers, !layers.isEmpty {
                parts.append("### Capability Layers")
                for layer in layers {
                    parts.append("- **\(layer.name)**: \(layer.capability) (\(layer.from_stage) → \(layer.to_stage))")
                }
                parts.append("")
            }
            if let measurements = evolution.measurement, !measurements.isEmpty {
                parts.append("### Measurement")
                for m in measurements {
                    parts.append("- **\(m.what)**: \(m.how) (threshold: \(m.threshold))")
                }
                parts.append("")
            }
        }

        // Inject old field name warnings if any
        let warnings = detectOldFieldNames(domain, domainName: domain.core.meta.domain)
        if !warnings.isEmpty {
            var warningParts: [String] = []
            warningParts.append("<!-- KDNA FIELD NAME WARNINGS:")
            for w in warnings { warningParts.append("  \(w)") }
            warningParts.append("  These fields will be SILENTLY IGNORED by the loader.")
            warningParts.append("-->")
            warningParts.append("")
            let prefix = warningParts.joined(separator: "\n")
            return prefix + "\n" + parts.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        }

        return parts.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Validation

    /// Validate a KDNA domain at a given path.
    public static func validate(path: String) -> KDNADomainValidationResult {
        let fileManager = FileManager.default
        var errors: [String] = []
        let warnings: [String] = []

        let requiredFiles = ["KDNA_Core.json", "KDNA_Patterns.json"]
        var fileCount = 0

        for file in requiredFiles {
            let filePath = (path as NSString).appendingPathComponent(file)
            if fileManager.fileExists(atPath: filePath) {
                fileCount += 1
            } else {
                errors.append("Missing required file: \(file)")
            }
        }

        // Count optional files
        let optionalFiles = ["KDNA_Scenarios.json", "KDNA_Cases.json", "KDNA_Reasoning.json", "KDNA_Evolution.json"]
        for file in optionalFiles {
            let filePath = (path as NSString).appendingPathComponent(file)
            if fileManager.fileExists(atPath: filePath) {
                fileCount += 1
            }
        }

        let schemaOK = errors.isEmpty
        return KDNADomainValidationResult(
            valid: errors.isEmpty,
            errors: errors,
            warnings: warnings,
            fileCount: fileCount,
            schemaOK: schemaOK
        )
    }

    // MARK: - Old Field Name Detection

    /// Map of old/informal field names → correct v1.0-rc spec field names.
    public static let fieldAliases: [String: String] = [
        "statement": "one_sentence or full_statement",
        "description": "one_sentence",
        "summary": "one_sentence",
        "claim": "wrong",
        "misreading": "wrong",
        "reality": "correct",
        "definition": "essence or one_sentence (on ontology)",
        "brief": "title or context",
        "bad_pattern": "what_happened",
        "master_pattern": "structural_pattern",
        "conclusion": "one_sentence",
        "capability_layers": "stages",
        "name": "id (on ontology entries — use id instead of name)",
        "input": "from",
        "output": "to",
        "judgment": "via",
    ]

    /// Recursively scan an object tree for known old field names and return warnings.
    public static func detectOldFieldNames(_ obj: Any, path: String = "", domainName: String = "domain") -> [String] {
        var warnings: [String] = []
        guard let dict = obj as? [String: Any] else {
            if let array = obj as? [Any] {
                for (i, item) in array.enumerated() {
                    warnings.append(contentsOf: detectOldFieldNames(item, path: "\(path)[\(i)]", domainName: domainName))
                }
            }
            return warnings
        }
        for (key, value) in dict {
            let fullPath = path.isEmpty ? key : "\(path).\(key)"
            if let alias = fieldAliases[key] {
                warnings.append("[KDNA Loader] \(domainName).\(fullPath): field '\(key)' is not in spec v1.0-rc. Use '\(alias)' instead.")
            }
            warnings.append(contentsOf: detectOldFieldNames(value, path: fullPath, domainName: domainName))
        }
        return warnings
    }

    // MARK: - Manifest Loading

    /// Load kdna.json manifest from a dev source directory.
    public static func loadManifest(from path: String) -> KDNAManifest? {
        let manifestPath = (path as NSString).appendingPathComponent("kdna.json")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)) else { return nil }
        return try? JSONDecoder().decode(KDNAManifest.self, from: data)
    }

    // MARK: - Private Helpers

    private static func loadJSON<T: Codable>(type: T.Type, basePath: String, filename: String) -> T? {
        let path = (basePath as NSString).appendingPathComponent(filename)
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    /// Determine which optional files to load based on user input text.
    private static func classifyInput(_ text: String) -> [String] {
        let lower = text.lowercased()
        var optional: [String] = []

        // Check for scenario-related keywords
        if lower.range(of: #"\b(situation|scenario|conflict|happened|tell\s+me\s+about|describe|instance|specific)\b"#, options: .regularExpression) != nil {
            optional.append("scenarios")
        }

        // Check for case-related keywords
        if lower.range(of: #"\b(example|demonstrat|full\s+case|show\s+me|sample|illustrate|walk\s+through|case)\b"#, options: .regularExpression) != nil {
            optional.append("cases")
        }

        // Check for reasoning-related keywords
        if lower.range(of: #"\b(why|rationale|principle|explain|reason|logic|how\s+come|cause)\b"#, options: .regularExpression) != nil {
            optional.append("reasoning")
        }

        // Check for evolution-related keywords
        if lower.range(of: #"\b(practice|improv|learn|grow|level|progress|measur|assess|evaluat|benchmark)\b"#, options: .regularExpression) != nil {
            optional.append("evolution")
        }

        return Array(Set(optional))
    }
}
