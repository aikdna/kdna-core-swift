import Foundation

/// Finite interpreter for the mechanically mirrored public component definition.
/// This reads static declarations; it never grants creation or action authority.
enum PublicComponents {
    static let codes = [
        "declaration": "READ_COMPONENT_DECLARATION_INVALID",
        "content": "READ_COMPONENT_CONTENT_INVALID",
        "reference": "READ_COMPONENT_REFERENCE_INVALID",
        "cycle": "READ_COMPONENT_GRAPH_CYCLE",
        "limit": "READ_COMPONENT_LIMIT_EXCEEDED",
        "binding": "READ_COMPONENT_BINDING_INVALID",
        "adoption": "READ_COMPONENT_ADOPTION_INVALID",
        "presence": "READ_METHOD_PRESENCE_INVALID"
    ]
    static func failure(_ kind: String, _ judgment: J = nil, _ component: J = nil) throws -> Never {
        let code = codes[kind]!
        throw PublicFailure(code, componentFailure: ["judgment_ref": judgment, "component_ref": component,
            "status": "invalid", "body": nil, "code": .string(code)])
    }
    static func hash(_ value: J) throws -> J { .string(sha(try KDNAJSON.canonical(value))) }
    static func before(_ a: J, _ b: J) -> Bool { a.text.utf8.lexicographicallyPrecedes(b.text.utf8) }
    static func pairBefore(_ a: J, _ b: J, _ first: String, _ second: String) -> Bool {
        a[first] == b[first] ? before(a[second], b[second]) : before(a[first], b[first])
    }
    static func descriptor(_ contract: J) throws -> J {
        let registry = contract["component_semantics"], d = registry["definition"]
        try demand(hash(d) == registry["definition_digest"], "READ_CORE_CAPABILITY_UNAVAILABLE")
        return ["contract_id": d["id"], "contract_version": d["version"], "definition_digest": registry["definition_digest"],
            "profiles": d["profiles"], "carriers": d["carriers"], "limits": d["limits"]]
    }
    static func decoded(_ value: J, _ kind: String, _ j: J = nil, _ c: J = nil) throws -> J {
        switch value["kind"].text {
        case "text", "number", "boolean": return value["value"]
        case "null": return nil
        case "list": return .array(try value["items"].list.map { try decoded($0, kind, j, c) })
        default:
            var result: [KDNAKey:J] = [:]
            for field in value["fields"].list {
                let key = KDNAKey(field["name"].text)
                if result[key] != nil { try failure(kind, j, c) }
                result[key] = try decoded(field["value"], kind, j, c)
            }
            return .object(result)
        }
    }
    /// Generated schema properties are canonical-key ordered. Paths deduplicate
    /// shared union branches while Extension.value remains entirely opaque.
    static func visitExtensions(_ payload: J, _ contract: J, _ callback: (J, [J]) throws -> Void) throws {
        var seen: Set<Data> = []
        let types = contract["types"]
        func walk(_ value: J, _ shape: J, _ path: [J]) throws {
            guard PublicSchema.typeMatches(value, "object") || PublicSchema.typeMatches(value, "array") else { return }
            if shape.has("$ref") {
                let name = String(shape["$ref"].text.dropFirst(8))
                if name == "Extension" {
                    if seen.insert(try KDNAJSON.canonical(.array(path))).inserted { try callback(value, path) }
                    return
                }
                try walk(value, types[name], path); return
            }
            for key in shape["properties"].fields.keys.sorted(by: { $0.text.utf16.lexicographicallyPrecedes($1.text.utf16) }) where value.has(key.text) {
                try walk(value[key.text], shape["properties"][key.text], path + [.string(key.text)])
            }
            if shape.has("items") { for (i, item) in value.list.enumerated() { try walk(item, shape["items"], path + [.number(Double(i))]) } }
            for branch in (shape.has("oneOf") ? shape["oneOf"] : shape["anyOf"]).list + shape["allOf"].list { try walk(value, branch, path) }
        }
        try walk(payload, types["Payload"], [])
    }
    static func checkNativeMethods(_ payload: J, _ definition: J) throws {
        for j in payload["judgments"].list {
            let m = j["method"]
            if m == .null || m["method"].has("extension") { continue }
            guard let requirement = definition["native_method_requirements"].list.first(where: { $0["term"] == m["method"]["term"] }) else { continue }
            for type in requirement["component_types"].list {
                try demand(m["components"].list.contains { $0["method"]["term"] == type && !$0["method"].has("extension") })
            }
            for role in requirement["binding_roles"].list { try demand(m["bindings"].list.contains { $0["role"] == role }) }
        }
    }
    // Exact ECMAScript TrimString set, including U+FEFF and excluding U+0085.
    static let trimScalars: Set<UInt32> = [9,10,11,12,13,32,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288,65279]
    static func text(_ value: J, _ maximum: J, _ j: J, _ c: J) throws {
        guard case .string(let s) = value, !s.isEmpty, scalar(s, maximum: Int(maximum.numeric)),
              let first = s.unicodeScalars.first, let last = s.unicodeScalars.last,
              !trimScalars.contains(first.value), !trimScalars.contains(last.value) else { try failure("content", j, c) }
    }
    static func grammar(_ name: String, _ value: J, _ contract: J, _ kind: String, _ j: J = nil, _ c: J = nil) throws {
        do { try PublicSchema.validate(name, value, contract) } catch { try failure(kind, j, c) }
    }
    static func plainProfile(_ type: J, _ content: J, _ j: J, _ c: J, _ contract: J) throws -> J {
        let limits = contract["component_semantics"]["definition"]["limits"]
        if !PublicSchema.typeMatches(content, "object") { try failure("content", j, c) }
        if Double(content["items"].list.count) > limits["items_per_component"].numeric { try failure("limit", j, c) }
        if type == "taxonomy" && Double(content["broader"].list.count) > limits["edges_per_component"].numeric { try failure("limit", j, c) }
        if type == "discriminator-set" && Double(content["items"].list.reduce(0, { $0 + $1["contrasts"].list.count })) > limits["edges_per_component"].numeric { try failure("limit", j, c) }
        let schema = type == "taxonomy" ? "TaxonomyContent" : type == "candidate-set" ? "CandidateSetContent" : "DiscriminatorContent"
        try grammar(schema, content, contract, "content", j, c)
        var keys: Set<KDNAKey> = [], keyOrder: [KDNAKey] = []
        for item in content["items"].list {
            let key = KDNAKey(item["key"].text)
            if !keys.insert(key).inserted { try failure("content", j, c) }; keyOrder.append(key)
            try text(item["title"], limits["title_utf8_bytes"], j, c)
            try text(item[type == "discriminator-set" ? "prompt" : "meaning"], limits["meaning_prompt_criterion_utf8_bytes"], j, c)
        }
        let items = content["items"].list.sorted { before($0["key"], $1["key"]) }
        if type == "taxonomy" {
            var edgeSet: Set<Data> = [], graph = Dictionary(uniqueKeysWithValues: keyOrder.map { ($0, [KDNAKey]()) })
            for edge in content["broader"].list {
                let narrower = KDNAKey(edge["narrowerKey"].text), broader = KDNAKey(edge["broaderKey"].text)
                if !keys.contains(narrower) || !keys.contains(broader) { try failure("reference", j, c) }
                if narrower == broader { try failure("cycle", j, c) }
                if !edgeSet.insert(try KDNAJSON.canonical([edge["narrowerKey"], edge["broaderKey"]])).inserted { try failure("content", j, c) }
                graph[narrower, default: []].append(broader)
            }
            var visiting: Set<KDNAKey> = [], longest: [KDNAKey:Int] = [:]
            func depth(_ key: KDNAKey, _ ancestors: Int) throws -> Int {
                if Double(ancestors) > limits["taxonomy_path_edges"].numeric { try failure("limit", j, c) }
                if visiting.contains(key) { try failure("cycle", j, c) }
                if let value = longest[key] { return value }
                visiting.insert(key); var value = 0
                for next in graph[key] ?? [] { value = max(value, 1 + (try depth(next, ancestors + 1))) }
                visiting.remove(key)
                if Double(value) > limits["taxonomy_path_edges"].numeric { try failure("limit", j, c) }
                longest[key] = value; return value
            }
            for key in keyOrder { _ = try depth(key, 0) }
            return ["kind": "taxonomy", "items": .array(items), "broader": .array(content["broader"].list.sorted { pairBefore($0, $1, "narrowerKey", "broaderKey") })]
        }
        if type == "candidate-set" { return ["kind": type, "items": .array(items)] }
        for item in content["items"].list {
            var candidates: Set<KDNAKey> = []
            for contrast in item["contrasts"].list {
                if !candidates.insert(KDNAKey(contrast["candidateKey"].text)).inserted { try failure("content", j, c) }
                try text(contrast["criterion"], limits["meaning_prompt_criterion_utf8_bytes"], j, c)
            }
        }
        return nil
    }
    private struct Entry { let value: J; var body: J; let owner: J }
    static func resolve(_ payload: J, _ contract: J) throws -> [KDNAKey:J] {
        let registry = contract["component_semantics"], definition = registry["definition"], D = registry["definition_digest"]
        _ = try descriptor(contract)
        let limits = definition["limits"], judgments = payload["judgments"].list
        try checkNativeMethods(payload, definition)
        var selected: [KDNAKey:Entry] = [:], selectedOrder: [KDNAKey] = [], presences: [KDNAKey:J] = [:], allValues: [J] = []
        var aggregate: J = nil, totalBytes = 0, seenPresence: Set<KDNAKey> = []
        if Double(judgments.reduce(0, { $0 + $1["method"]["components"].list.count })) > limits["components_per_payload"].numeric { try failure("limit") }
        for j in judgments where j.has("method") { presences[KDNAKey(j["id"].text)] = ["components_state": "declared", "bindings_state": "declared"] }
        try visitExtensions(payload, contract) { ext, path in
            guard let registered = definition["carriers"].fields.first(where: { $0.value["id"] == ext["id"] }) else {
                if ext["critical"].boolean { throw PublicFailure("READ_INTERPRETATION_INCOMPLETE") }; return
            }
            let judgmentPosition = path.count == 4 && path[0] == "judgments" && path[2] == "extensions"
            let payloadPosition = path.count == 2 && path[0] == "extensions"
            let judgment: J = judgmentPosition ? judgments[Int(path[1].numeric)] : nil
            let j = judgment["id"], kind = registered.key.text, errorKind = kind == "component" ? "declaration" : kind
            if !ext["critical"].boolean || ext["definition"] != registered.value["definition"] || (kind == "adoption" ? !payloadPosition : !judgmentPosition) { try failure(errorKind, j) }
            let value = try decoded(ext["value"], errorKind, j)
            if !PublicSchema.typeMatches(value, "object") { try failure(errorKind, j) }
            if kind == "presence" {
                try grammar("MethodPresenceCarrier", value, contract, "presence", j)
                if !judgment.has("method") || value["judgment_ref"] != j || seenPresence.contains(KDNAKey(j.text)) || (value["components_state"] == "declared" && value["bindings_state"] == "declared") { try failure("presence", j) }
                if (value["components_state"] == "undeclared" && !judgment["method"]["components"].list.isEmpty) || (value["bindings_state"] == "undeclared" && !judgment["method"]["bindings"].list.isEmpty) { try failure("presence", j) }
                seenPresence.insert(KDNAKey(j.text)); presences[KDNAKey(j.text)] = ["components_state": value["components_state"], "bindings_state": value["bindings_state"]]; return
            }
            if kind == "adoption" {
                try grammar("ComponentAdoptionCarrier", value, contract, "adoption")
                if aggregate != .null { try failure("adoption") }; aggregate = value; return
            }
            if !judgment.has("method") || value["judgment_ref"] != j { try failure("reference", j) }
            guard let component = judgment["method"]["components"].list.first(where: { $0["id"] == value["component_ref"] }) else { try failure("reference", j) }
            let c = component["id"], key = KDNAKey(c.text)
            let profile = definition["profiles"].list.first { $0["component_type"] == component["method"]["term"] }?["profile_id"] ?? nil
            if selected[key] != nil || component["method"].has("extension") || profile == .null || value["component_type"] != component["method"]["term"] || value["profile_id"] != profile || value["contract_id"] != definition["id"] || value["contract_version"] != definition["version"] || value["definition_digest"] != D { try failure("declaration", j, c) }
            let contentBytes: Data
            do { contentBytes = try KDNAJSON.canonical(value["content"]) } catch { try failure("content", j, c) }
            totalBytes += contentBytes.count
            if Double(contentBytes.count) > limits["content_canonical_bytes"].numeric || Double(totalBytes) > limits["opted_in_total_canonical_bytes"].numeric { try failure("limit", j, c) }
            let body = try plainProfile(component["method"]["term"], value["content"], j, c, contract)
            try grammar("ComponentSemanticsCarrier", value, contract, "declaration", j, c)
            if value["content_digest"] != .string(sha(contentBytes)) { try failure("binding", j, c) }
            if value["statement_origin"] == "mechanical_content_representation" && component["statement"] != .string(String(decoding: contentBytes, as: UTF8.self)) { try failure("declaration", j, c) }
            if try value["component_declaration_digest"] != hash(["component": component, "statement_origin": value["statement_origin"]]) { try failure("binding", j, c) }
            let bindings = judgment["method"]["bindings"].list.filter { $0["component_ref"] == c }.sorted { pairBefore($0, $1, "role", "target_ref") }
            var seen: Set<Data> = []
            for binding in bindings {
                if try binding["target_ref"] != j || !seen.insert(KDNAJSON.canonical(binding)).inserted { try failure("binding", j, c) }
            }
            if try value["bindings_digest"] != hash(.array(bindings)) { try failure("binding", j, c) }
            selected[key] = Entry(value: value, body: body, owner: j); selectedOrder.append(key); allValues.append(value)
        }
        for c in selectedOrder {
            var entry = selected[c]!
            let value = entry.value, j = entry.owner
            if value["component_type"] != "discriminator-set" { continue }
            guard let target = selected[KDNAKey(value["content"]["candidateSetRef"].text)], target.owner == j, target.value["component_type"] == "candidate-set" else { try failure("reference", j, .string(c.text)) }
            let keys = Set(target.value["content"]["items"].list.map { KDNAKey($0["key"].text) })
            for item in value["content"]["items"].list { for contrast in item["contrasts"].list where !keys.contains(KDNAKey(contrast["candidateKey"].text)) { try failure("reference", j, .string(c.text)) } }
            let items: [J] = value["content"]["items"].list.sorted { before($0["key"], $1["key"]) }.map { original in
                var item = original; item["contrasts"] = .array(item["contrasts"].list.sorted { before($0["candidateKey"], $1["candidateKey"]) }); return item
            }
            entry.body = ["kind": "discriminator-set", "candidateSetRef": value["content"]["candidateSetRef"],
                "candidateIndex": .array(target.body["items"].list.map { ["key": $0["key"], "title": $0["title"]] }), "items": .array(items)]
            selected[c] = entry
        }
        if (aggregate != .null) != !selected.isEmpty { try failure("adoption") }
        if aggregate != .null {
            allValues.sort { pairBefore($0, $1, "judgment_ref", "component_ref") }
            let proposals = Set(allValues.map { KDNAKey($0["adoption_proposal_digest"].text) }).map { J.string($0.text) }.sorted(by: before)
            if aggregate["contract_id"] != definition["id"] || aggregate["contract_version"] != definition["version"] || aggregate["definition_digest"] != D { try failure("adoption") }
            if try aggregate["declaration_set_digest"] != hash(.array(allValues)) || aggregate["proposal_set_digest"] != hash(.array(proposals)) { try failure("adoption") }
        }
        var methods: [KDNAKey:J] = [:]
        for j in judgments where j.has("method") {
            let interpretations: [J] = try j["method"]["components"].list.map { component in
                var value: J = ["judgment_ref": j["id"], "component_ref": component["id"], "component_type": component["method"]["term"], "definition_digest": D,
                    "status": "undeclared", "declaration_digest": nil, "content_digest": nil, "profile_id": nil, "component_declaration_digest": nil,
                    "statement_origin": nil, "bindings_digest": nil, "adoption_proposal_digest": nil, "authored_content": nil, "body": nil]
                if let entry = selected[KDNAKey(component["id"].text)] {
                    value["status"] = "supported"; value["declaration_digest"] = try hash(entry.value)
                    for key in ["content_digest", "profile_id", "component_declaration_digest", "statement_origin", "bindings_digest", "adoption_proposal_digest"] { value[key] = entry.value[key] }
                    value["authored_content"] = entry.value["content"]; value["body"] = entry.body
                }
                return value
            }
            methods[KDNAKey(j["id"].text)] = ["declaration": j["method"], "declaration_presence": presences[KDNAKey(j["id"].text)]!, "component_interpretations": .array(interpretations)]
        }
        return methods
    }
}
