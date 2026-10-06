import Foundation

// The 0.5-generation static-policy semantics (static-policy-semantics.js,
// @aikdna/kdna-core@0.36.0): the single critical carrier per judgment, its
// rule digest, priority semantics and candidate validation. Failures are
// READ_STATIC_POLICY_INVALID; the JS utf8()/canonicalJson 1 MiB cap surfaces
// as READ_INPUT_INVALID (coded), not as a raw error.
enum StaticPolicySemantics {
    static func definitionContract() throws -> (definition: J, digest: String) {
        let contract = try SemanticContract.loadedContract.get()
        let definition = contract["static_policy"]["definition"], digest = contract["static_policy"]["definition_digest"].text
        guard sha(try KDNAJSON.canonical(definition)) == digest else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        return (definition, digest)
    }
    static func fail() throws -> Never { throw PublicFailure("READ_STATIC_POLICY_INVALID") }
    static func decode(_ value: J) throws -> J {
        switch value["kind"].text {
        case "text", "number", "boolean": return value["value"]
        case "null": return .null
        case "list": return .array(try value["items"].list.map { try decode($0) })
        default:
            var out: [KDNAKey: J] = [:]
            var seen = Set<String>()
            for field in value["fields"].list {
                if !seen.insert(R2Registry.canonicalKey(field["name"])).inserted { try fail() }
                out[KDNAKey(field["name"].text)] = try decode(field["value"])
            }
            return .object(out)
        }
    }
    static func text(_ value: J, _ maximum: Int) throws {
        guard case .string(let text) = value, !text.isEmpty,
              Array(text.unicodeScalars).first.map({ !ComponentSemantics.jsWhitespace($0) }) ?? false,
              Array(text.unicodeScalars).last.map({ !ComponentSemantics.jsWhitespace($0) }) ?? false,
              scalar(text, maximum: maximum, controls: true) else { try fail() }
    }
    static func resolveStaticPolicies(_ payload: J, _ validateCandidate: (J, J) throws -> Void) throws -> [String: J] {
        let (definition, digest) = try definitionContract()
        let limits = definition["limits"]
        let carrier = definition["carrier"]
        var result: [String: J] = [:]
        var total = 0
        try ComponentSemantics.visitExtensions(payload) { extensionValue, path in
            if !exact(extensionValue["id"].text, carrier["id"].text) { return }
            let rightPosition = path.count == 4 && path[0] == .key("judgments") && path[2] == .key("extensions")
            if !rightPosition || !extensionValue["critical"].boolean || !exact(extensionValue["definition"].text, carrier["definition"].text) { try fail() }
            guard case .index(let position) = path[1] else { try fail() }
            let judgment = payload["judgments"].list[position]
            let value = try decode(extensionValue["value"])
            do { _ = try SemanticContract.validate("StaticPolicyCarrier", value) } catch { try fail() }
            if !exact(value["contract_id"].text, definition["id"].text) || !exact(value["contract_version"].text, definition["version"].text)
                || !exact(value["definition_digest"].text, digest) || !exact(value["judgment_ref"].text, judgment["id"].text)
                || result[judgment["id"].text] != nil { try fail() }
            let rule = value["rule"], formation = judgment["formation_rule"]
            if formation == .null || !formation["condition_refs"].list.isEmpty || formation["policy"] != .null
                || !exact(rule["output_contract_ref"].text, formation["output_contract_ref"].text)
                || !exact(rule["output_contract_ref"].text, judgment["result_contract"]["id"].text) { try fail() }
            var bytes: Int
            do { bytes = try KDNAJSON.canonical(rule).count } catch { throw PublicFailure("READ_INPUT_INVALID") }
            if bytes > 1048576 { throw PublicFailure("READ_INPUT_INVALID") }
            total += bytes
            let ruleDigest = sha(try KDNAJSON.canonical(rule))
            if bytes > Int(limits["rule_canonical_bytes"].numeric) || total > Int(limits["total_rule_canonical_bytes"].numeric) || !exact(ruleDigest, value["rule_digest"].text) { try fail() }
            var candidates = Set<String>()
            for candidate in rule["candidates"].list {
                if !candidates.insert(candidate["key"].text).inserted { try fail() }
                try text(candidate["title"], Int(limits["title_utf8_bytes"].numeric))
                try text(candidate["meaning"], Int(limits["text_utf8_bytes"].numeric))
                do { try validateCandidate(judgment, candidate) } catch { try fail() }
            }
            var entries = Set<String>(), priorities = Set<Int>()
            for entry in rule["entries"].list {
                guard isUInt(entry["priority"]), candidates.contains(entry["candidate_key"].text) else { try fail() }
                if !entries.insert(entry["key"].text).inserted || !priorities.insert(Int(entry["priority"].numeric)).inserted { try fail() }
                try text(entry["condition"]["statement"], Int(limits["text_utf8_bytes"].numeric))
            }
            if rule["fallback"]["kind"].text == "candidate" {
                if !candidates.contains(rule["fallback"]["candidate_key"].text) { try fail() }
            } else {
                try text(rule["fallback"]["statement"], Int(limits["text_utf8_bytes"].numeric))
            }
            var normalized = rule
            normalized["candidates"] = .array(rule["candidates"].list.sorted { SectionFrameGraph.utf8Less($0["key"].text, $1["key"].text) })
            let higherFirst = rule["strategy"]["direction"].text == "higher-first"
            normalized["entries"] = .array(rule["entries"].list.sorted {
                let left = $0["priority"].numeric, right = $1["priority"].numeric
                return higherFirst ? right < left : left < right
            })
            result[judgment["id"].text] = ["contract_id": definition["id"], "contract_version": definition["version"], "definition_digest": .string(digest),
                                           "judgment_ref": judgment["id"], "declaration_digest": .string(sha(try KDNAJSON.canonical(value))),
                                           "rule_digest": value["rule_digest"], "authored_rule": rule, "rule": normalized, "status": "supported"]
        }
        return result
    }
}
