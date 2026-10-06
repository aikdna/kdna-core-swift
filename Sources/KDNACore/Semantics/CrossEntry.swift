import Foundation

// Cross-entry obligations of the 0.5 grammar (cross-entry.js,
// @aikdna/kdna-core@0.36.0): form consistency, asset capability, unique
// identity (top-level collections plus the nested resolution targets),
// definition-term uniqueness, parent closure, core-term vocabulary,
// the navigation-label ban and lifecycle replacement rules. Rule ids,
// violation paths and messages are verbatim (the reports are observable),
// and assertPayload surfaces the first violation as READ_CORE_INVALID with
// its field pointer and rule id.
enum CrossEntry {
    struct Violation {
        let path: String
        let message: String
    }
    struct Rule {
        let id: String
        let run: (J, J) throws -> [Violation]
    }
    static let formConclusion = "conclusion", formRule = "rule"
    static let identityCollections = ["judgments", "materials", "reasons", "sources", "source_uses", "resources", "relationships", "dependencies", "actors", "extensions"]
    static func quote(_ value: J) -> String { (try? String(decoding: KDNAJSON.canonical(value), as: UTF8.self)) ?? "" }
    static func describe(_ value: J) -> String {
        if case .array(let items) = value { return "array(\(items.count))" }
        switch value {
        case .bool: return "boolean"; case .number: return "number"; case .string: return "string"; case .object: return "object"; case .null: return "null"; case .array: return "array"
        }
    }
    static func describeOptional(_ value: J?) -> String { value.map { $0 == .null ? "null" : describe($0) } ?? "absent" }
    static func judgements(_ payload: J) -> [J] { payload["judgments"].list }
    static func termOf(_ ref: J) -> String? { ref["term"] == .null ? nil : ref["term"].text }
    static func ruleFormConsistency(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        for (index, judgment) in judgements(payload).enumerated() {
            guard case .object = judgment else { continue }
            let at = "/judgments/\(index)"
            let hasResult = judgment.has("result"), hasRule = judgment.has("formation_rule")
            if judgment.has("form") && !exact(judgment["form"].text, formConclusion) && !exact(judgment["form"].text, formRule) {
                out.append(Violation(path: at + "/form", message: "form must be one of \(quote(.array([.string(formConclusion), .string(formRule)]))); found the declared value in an unregistered form"))
            }
            if !hasResult && !hasRule { out.append(Violation(path: at + "/form", message: "exactly one of result or formation_rule is required; neither is present")) }
            if hasResult && hasRule { out.append(Violation(path: at + "/form", message: "exactly one of result or formation_rule is allowed; both are present")) }
            if exact(judgment["form"].text, formConclusion) {
                if !hasResult { out.append(Violation(path: at + "/result", message: "form \"conclusion\" requires an actual result")) }
                if !judgment.has("result_contract") { out.append(Violation(path: at + "/result_contract", message: "form \"conclusion\" requires a result_contract")) }
                if hasRule { out.append(Violation(path: at + "/formation_rule", message: "form \"conclusion\" forbids a formation_rule")) }
            } else if exact(judgment["form"].text, formRule) {
                if !hasRule { out.append(Violation(path: at + "/formation_rule", message: "form \"rule\" requires a formation_rule")) }
                if hasResult { out.append(Violation(path: at + "/result", message: "form \"rule\" forbids a result")) }
            }
        }
        return out
    }
    static func capabilityFor(_ payload: J) -> String? {
        var forms: [String] = []
        for judgment in judgements(payload) {
            guard case .object = judgment else { continue }
            forms.append(judgment["form"].text)
        }
        if forms.isEmpty { return nil }
        if forms.contains(where: { $0 != formConclusion && $0 != formRule }) { return nil }
        let distinct = Set(forms)
        if distinct.count != 1 { return "mixed" }
        return distinct.first == formConclusion ? "asserted_answers" : "result_forming_rules"
    }
    static func ruleAssetCapability(_ payload: J, _ registry: J) -> [Violation] {
        guard let expected = capabilityFor(payload) else {
            return [Violation(path: "/asset_capability", message: "asset capability cannot be derived because at least one judgment declares no closed form")]
        }
        if payload["asset_capability"].text != expected {
            var declared: J? = nil
            if payload.has("asset_capability") { declared = payload["asset_capability"] }
            return [Violation(path: "/asset_capability", message: "asset_capability \(describeOptional(declared)) contradicts the declared judgment forms; the closed mapping of this asset is \(quote(.string(expected))). The asset-level value is a summary; the issue-level form stays authoritative.")]
        }
        return []
    }
    static func pushDuplicates(_ out: inout [Violation], _ kind: String, _ entries: [J], _ pathFor: (Int) -> String) {
        var first: [String: Int] = [:]
        for (index, entry) in entries.enumerated() {
            guard case .object = entry else { continue }
            let id = entry["id"].text
            if id.isEmpty { continue }
            if let previous = first[id] {
                out.append(Violation(path: pathFor(index), message: "duplicate \(kind) id \(quote(.string(id))); first declared at \(pathFor(previous)). One id must name one object inside its class."))
                continue
            }
            first[id] = index
        }
    }
    static func declarationValues(_ declaration: J) -> [J] { declaration["value"].list }
    static func nestedIdentityViolations(_ payload: J) -> [Violation] {
        var out: [Violation] = []
        var contracts: [String: Int] = [:]
        for (index, judgment) in judgements(payload).enumerated() {
            guard case .object = judgment, case .object = judgment["result_contract"] else { continue }
            let id = judgment["result_contract"]["id"].text
            if id.isEmpty { continue }
            if let previous = contracts[id] {
                out.append(Violation(path: "/judgments/\(index)/result_contract/id", message: "duplicate result_contract id \(quote(.string(id))); first declared by /judgments/\(previous). A result contract id is a resolution target, so one id must name one contract."))
                continue
            }
            contracts[id] = index
        }
        var seenExtensions: [String: String] = [:]
        for (index, entry) in payload["extensions"].list.enumerated() {
            guard case .object = entry else { continue }
            let id = entry["id"].text
            if id.isEmpty { continue }
            let path = "/extensions/\(index)/id"
            if let previous = seenExtensions[id] {
                out.append(Violation(path: path, message: "duplicate Extension id \(quote(.string(id))); first declared at \(previous)"))
                continue
            }
            seenExtensions[id] = path
        }
        var boundaryEntries: [(J, String)] = [], exceptionEntries: [(J, String)] = [], misuseEntries: [(J, String)] = []
        let assetDeclarations = payload["declarations"]
        for (index, entry) in declarationValues(assetDeclarations["boundaries"]).enumerated() {
            boundaryEntries.append((entry, "/declarations/boundaries/value/\(index)/id"))
        }
        for (index, judgment) in judgements(payload).enumerated() {
            guard case .object = judgment else { continue }
            for (position, entry) in declarationValues(judgment["boundaries"]).enumerated() { boundaryEntries.append((entry, "/judgments/\(index)/boundaries/value/\(position)/id")) }
            for (position, entry) in declarationValues(judgment["exceptions"]).enumerated() { exceptionEntries.append((entry, "/judgments/\(index)/exceptions/value/\(position)/id")) }
            for (position, entry) in declarationValues(judgment["misuse"]).enumerated() { misuseEntries.append((entry, "/judgments/\(index)/misuse/value/\(position)/id")) }
        }
        func dedupe(_ entries: [(J, String)], _ kind: String) {
            var seen: [String: String] = [:]
            for (entry, path) in entries {
                guard case .object = entry else { continue }
                let id = entry["id"].text
                if id.isEmpty { continue }
                if let previous = seen[id] {
                    out.append(Violation(path: path, message: "duplicate \(kind) id \(quote(.string(id))); first declared at \(previous)"))
                    continue
                }
                seen[id] = path
            }
        }
        dedupe(boundaryEntries, "Boundary")
        dedupe(exceptionEntries, "Exception")
        dedupe(misuseEntries, "Misuse")
        var seenComponents: [String: String] = [:]
        for (index, judgment) in judgements(payload).enumerated() {
            guard case .object = judgment, case .object = judgment["method"] else { continue }
            for (position, component) in judgment["method"]["components"].list.enumerated() {
                guard case .object = component else { continue }
                let id = component["id"].text
                if id.isEmpty { continue }
                let path = "/judgments/\(index)/method/components/\(position)/id"
                if let previous = seenComponents[id] {
                    out.append(Violation(path: path, message: "duplicate MethodComponent id \(quote(.string(id))); first declared at \(previous). A method component id is a resolution target of the whole asset, so one id must name one component even across different judgments."))
                    continue
                }
                seenComponents[id] = path
            }
        }
        return out
    }
    static func ruleUniqueIdentity(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        for key in identityCollections {
            let kind = key == "extensions" ? "Extension" : String(key.dropLast())
            pushDuplicates(&out, kind, payload[key].list) { "/\(key)/\($0)/id" }
        }
        return out + nestedIdentityViolations(payload)
    }
    static func ruleTermUniqueness(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        var seen: [String: Int] = [:]
        for (index, material) in payload["materials"].list.enumerated() {
            guard case .object = material, material["kind"].text == "definition" else { continue }
            let term = material["term"].text
            if material.has("term") && term.isEmpty {
                out.append(Violation(path: "/materials/\(index)/term", message: "a definition term must be a non-empty string; found \(describe(material["term"]))"))
                continue
            }
            if term.isEmpty { continue }
            if let previous = seen[term] {
                out.append(Violation(path: "/materials/\(index)/term", message: "duplicate definition term \(quote(.string(term))); first declared at /materials/\(previous)/term. Duplicates are rejected, never merged by the reader."))
                continue
            }
            seen[term] = index
        }
        return out
    }
    static func ruleParentClosure(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        let judgments = judgements(payload)
        var ids: [String: Int] = [:], idCounts: [String: Int] = [:]
        for (index, judgment) in judgments.enumerated() {
            guard case .object = judgment, case .string = judgment["id"] else { continue }
            let id = judgment["id"].text
            idCounts[id, default: 0] += 1
            if ids[id] == nil { ids[id] = index }
        }
        var parentOf: [String: String] = [:]
        for (index, judgment) in judgments.enumerated() {
            guard case .object = judgment, judgment.has("parent_ref") else { continue }
            let path = "/judgments/\(index)/parent_ref"
            let raw = judgment["parent_ref"]
            if raw == .null { continue }
            if raw.text.isEmpty {
                out.append(Violation(path: path, message: "parent_ref must be a non-empty identifier; found \(describe(raw))"))
                continue
            }
            if case .string = judgment["id"] {
                let id = judgment["id"].text
                if (idCounts[id] ?? 0) > 1 {
                    out.append(Violation(path: path, message: "parent_ref cannot be evaluated because judgment id \(quote(.string(id))) is declared \(idCounts[id]!) times in this asset"))
                    continue
                }
                parentOf[id] = raw.text
            }
            if exact(raw.text, judgment["id"].text) {
                out.append(Violation(path: path, message: "parent_ref points at its own judgment (\(quote(.string(raw.text))))"))
                continue
            }
            if ids[raw.text] == nil { out.append(Violation(path: path, message: "parent_ref \(quote(.string(raw.text))) does not resolve to any judgment id in this asset")) }
        }
        var settled = Set<String>()
        for start in parentOf.keys {
            if settled.contains(start) { continue }
            var chain: [String] = []
            var node: String? = start
            while let current = node, parentOf[current] != nil {
                if chain.contains(current) {
                    let index = judgments.firstIndex { if case .object = $0, exact($0["id"].text, start) { return true }; return false }
                    out.append(Violation(path: index.map { "/judgments/\($0)/parent_ref" } ?? "/judgments",
                                         message: "parent_ref cycle detected: \(chain.map { quote(.string($0)) }.joined(separator: " -> ")) -> \(quote(.string(current)))"))
                    break
                }
                chain.append(current)
                node = parentOf[current]
            }
            for visited in chain { settled.insert(visited) }
        }
        return out
    }
    static func ruleTermVocabulary(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        func check(_ ref: J, _ key: String, _ path: String) {
            guard let term = termOf(ref) else { return }
            let known = registry[key].list.contains { exact($0.text, term) }
            if known || ref["vocabulary"].text == "author" { return }
            var declared: J? = nil
            if ref.has("vocabulary") { declared = ref["vocabulary"] }
            out.append(Violation(path: path + "/term", message: "term \(quote(.string(term))) is not in core_terms.\(key) and vocabulary is \(describeOptional(declared)); either register the term or declare vocabulary:\"author\""))
        }
        for (index, relationship) in payload["relationships"].list.enumerated() {
            guard case .object = relationship else { continue }
            check(relationship["kind"], "relationship_kind", "/relationships/\(index)/kind")
            check(relationship["operator"], "relationship_operator", "/relationships/\(index)/operator")
            check(relationship["effect"], "relationship_effect", "/relationships/\(index)/effect")
            for (position, participant) in relationship["participants"].list.enumerated() where isObjectValue(participant) {
                check(participant["role"], "relation_role", "/relationships/\(index)/participants/\(position)/role")
            }
        }
        for (index, judgment) in judgements(payload).enumerated() {
            guard case .object = judgment else { continue }
            if isObjectValue(judgment["result_contract"]) {
                check(judgment["result_contract"]["form"], "answer_type", "/judgments/\(index)/result_contract/form")
                for (position, term) in judgment["result_contract"]["allowed_result_types"].list.enumerated() {
                    check(term, "answer_type", "/judgments/\(index)/result_contract/allowed_result_types/\(position)")
                }
            }
            if isObjectValue(judgment["result"]) { check(judgment["result"]["result_type"], "answer_type", "/judgments/\(index)/result/result_type") }
            if isObjectValue(judgment["method"]) {
                check(judgment["method"]["method"], "method", "/judgments/\(index)/method/method")
                for (position, component) in judgment["method"]["components"].list.enumerated() where isObjectValue(component) {
                    check(component["method"], "method", "/judgments/\(index)/method/components/\(position)/method")
                }
            }
        }
        return out
    }
    static func isObjectValue(_ value: J) -> Bool { if case .object = value { return true }; return false }
    static func ruleNavigationLabel(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        for (index, judgment) in judgements(payload).enumerated() where isObjectValue(judgment) && judgment.has("label") {
            out.append(Violation(path: "/judgments/\(index)/label", message: "R2 uses the unique authored focus; a separate navigation label is forbidden"))
        }
        return out
    }
    static func ruleLifecycle(_ payload: J, _ registry: J) -> [Violation] {
        var out: [Violation] = []
        let judgments = judgements(payload)
        var byId: [String: J] = [:]
        for judgment in judgments { byId[judgment["id"].text] = judgment }
        var edgesOrder: [String] = []
        var edges: [String: [String]] = [:]
        for (index, judgment) in judgments.enumerated() {
            guard isObjectValue(judgment), judgment.has("lifecycle") else { continue }
            let lifecycle = judgment["lifecycle"], at = "/judgments/\(index)/lifecycle"
            let status = lifecycle["status"].text
            guard isObjectValue(lifecycle), ["active", "deprecated", "superseded", "withdrawn"].contains(status),
                  case .array(let targets) = lifecycle["superseded_by"] else {
                out.append(Violation(path: at, message: "lifecycle must use the closed status and replacement target contract"))
                continue
            }
            if status == "superseded" && targets.isEmpty { out.append(Violation(path: at + "/superseded_by", message: "superseded requires an explicit replacement")) }
            if ["active", "withdrawn"].contains(status) && !targets.isEmpty { out.append(Violation(path: at + "/superseded_by", message: "active and withdrawn forbid replacement assertions; use deprecated or superseded")) }
            var local: [String] = []
            var seen = Set<String>()
            for (position, target) in targets.enumerated() {
                let path = "\(at)/superseded_by/\(position)"
                let asset = target["asset"]
                let completeAsset = ["asset_id", "asset_version", "judgment_version"].allSatisfy { !asset[$0].text.isEmpty }
                if !isObjectValue(target) || !isObjectValue(asset) || !completeAsset || target["judgment_id"].text.isEmpty {
                    out.append(Violation(path: path, message: "replacement requires complete AssetIdentity and judgment_id"))
                    continue
                }
                let key = R2Registry.canonicalKey(.array([asset["asset_id"], asset["asset_version"], asset["judgment_version"], target["judgment_id"]]))
                if seen.contains(key) { out.append(Violation(path: path, message: "replacement identity must be unique")) }
                seen.insert(key)
                if !R2Registry.sameAsset(asset, payload["asset"]) { continue }
                if target["judgment_id"].text == judgment["id"].text { out.append(Violation(path: path, message: "a judgment cannot replace itself")) }
                if byId[target["judgment_id"].text] == nil {
                    out.append(Violation(path: path, message: "a current-asset replacement must resolve to a judgment"))
                } else {
                    local.append(target["judgment_id"].text)
                }
            }
            edges[judgment["id"].text] = local
            edgesOrder.append(judgment["id"].text)
        }
        var colors: [String: Int] = [:]
        for id in edgesOrder where colors[id] == nil {
            if colors[id] == 2 { continue }
            var stack: [(String, Int)] = [(id, 0)]
            colors[id] = 1
            while !stack.isEmpty {
                let (current, index) = stack[stack.count - 1]
                let targets = edges[current] ?? []
                if index == targets.count { colors[current] = 2; stack.removeLast(); continue }
                stack[stack.count - 1].1 += 1
                let next = targets[index]
                if colors[next] == 1 {
                    out.append(Violation(path: "/judgments", message: "current-asset replacement graph must be acyclic"))
                    return out
                }
                if colors[next] != 2 {
                    colors[next] = 1
                    stack.append((next, 0))
                }
            }
        }
        return out
    }
    static var rules: [Rule] {
        [Rule(id: "PUBLIC-FORM-CONSISTENCY", run: ruleFormConsistency),
         Rule(id: "PUBLIC-ASSET-CAPABILITY", run: ruleAssetCapability),
         Rule(id: "PUBLIC-UNIQUE-IDENTITY", run: ruleUniqueIdentity),
         Rule(id: "PUBLIC-TERM-UNIQUENESS", run: ruleTermUniqueness),
         Rule(id: "PUBLIC-PARENT-CLOSURE", run: ruleParentClosure),
         Rule(id: "PUBLIC-TERM-VOCABULARY", run: ruleTermVocabulary),
         Rule(id: "PUBLIC-NAVIGATION-LABEL", run: ruleNavigationLabel),
         Rule(id: "PUBLIC-LIFECYCLE", run: ruleLifecycle)]
    }
    static func checkPayload(_ payload: J, _ registry: J) throws -> J {
        var report: [J] = []
        for rule in rules {
            let violations = try rule.run(payload, registry)
            report.append(["rule_id": .string(rule.id), "ok": .bool(violations.isEmpty),
                           "violations": .array(violations.map { ["rule_id": .string(rule.id), "path": .string($0.path), "message": .string($0.message)] })])
        }
        return .array(report)
    }
    static func assertPayload(_ payload: J, _ registry: J) throws {
        for rule in rules {
            let violations = try rule.run(payload, registry)
            guard let first = violations.first else { continue }
            throw PublicFailure("READ_CORE_INVALID", field: "/payload" + first.path, subject: nil, crossEntryRule: rule.id)
        }
    }
}
