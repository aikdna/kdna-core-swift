import Foundation

// The 0.5-generation component semantics (component-semantics.js,
// @aikdna/kdna-core@0.36.0): carrier registry, profiles, limits, extension
// walking, method presence/adoption carriers and the component declarations
// with their digest bindings. READ_COMPONENT_* / READ_METHOD_PRESENCE_INVALID
// codes and the component_failure body are verbatim.
//
// Path identity: the Node walk dedups Extension visits by object identity;
// parsed JSON values have no aliasing, so the first schema position typing a
// node as Extension corresponds 1:1 to a traversal path — the path set here
// (distinguishing keys from indices) reproduces that identity exactly.
enum ComponentSemantics {
    enum PathElement: Hashable {
        case key(String)
        case index(Int)
    }
    static let codes: [String: String] = [
        "declaration": "READ_COMPONENT_DECLARATION_INVALID", "content": "READ_COMPONENT_CONTENT_INVALID",
        "reference": "READ_COMPONENT_REFERENCE_INVALID", "cycle": "READ_COMPONENT_GRAPH_CYCLE",
        "limit": "READ_COMPONENT_LIMIT_EXCEEDED", "binding": "READ_COMPONENT_BINDING_INVALID",
        "adoption": "READ_COMPONENT_ADOPTION_INVALID", "presence": "READ_METHOD_PRESENCE_INVALID",
    ]
    static func failure(_ kind: String, _ judgment: J = nil, _ component: J = nil) throws -> Never {
        let reason = codes[kind]!
        throw PublicFailure(reason, componentFailure: ["judgment_ref": judgment, "component_ref": component, "status": "invalid", "body": nil, "code": .string(reason)])
    }
    static func definitionContract() throws -> (definition: J, digest: String, kinds: [String: J], profiles: [String: String]) {
        let contract = try SemanticContract.loadedContract.get()
        let definition = contract["component_semantics"]["definition"], digest = contract["component_semantics"]["definition_digest"].text
        guard sha(try KDNAJSON.canonical(definition)) == digest else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        var kinds: [String: J] = [:]
        for (kind, carrier) in definition["carriers"].fields {
            var value: J = ["kind": .string(kind.text)]
            for (key, field) in carrier.fields { value[key.text] = field }
            kinds[carrier["id"].text] = value
        }
        var profiles: [String: String] = [:]
        for profile in definition["profiles"].list { profiles[profile["component_type"].text] = profile["profile_id"].text }
        return (definition, digest, kinds, profiles)
    }
    static func jsonValue(_ value: J, _ kind: String, _ judgment: J = nil, _ component: J = nil) throws -> J {
        switch value["kind"].text {
        case "text", "number", "boolean": return value["value"]
        case "null": return .null
        case "list": return .array(try value["items"].list.map { try jsonValue($0, kind, judgment, component) })
        default:
            var out: [KDNAKey: J] = [:]
            var seen = Set<String>()
            for field in value["fields"].list {
                let name = field["name"].text
                if !seen.insert(R2Registry.canonicalKey(field["name"])).inserted { try failure(kind, judgment, component) }
                out[KDNAKey(name)] = try jsonValue(field["value"], kind, judgment, component)
            }
            return .object(out)
        }
    }
    // Walk only positions typed as Extension; Extension.value is opaque here.
    static func visitExtensions(_ value: J, _ rootType: String = "Payload", _ callback: (J, [PathElement]) throws -> Void) throws {
        let contract = try SemanticContract.loadedContract.get(), types = contract["types"]
        var seen = Set<[PathElement]>()
        func walk(_ value: J, _ shape: J, _ path: [PathElement]) throws {
            if case .object = value {} else if case .array = value {} else { return }
            if shape.has("$ref") {
                let name = String(shape["$ref"].text.dropFirst(8))
                if name == "Extension" {
                    if seen.insert(path).inserted { try callback(value, path) }
                    return
                }
                return try walk(value, types[name], path)
            }
            for (key, child) in shape["properties"].fields where value.has(key.text) {
                try walk(value[key.text], child, path + [.key(key.text)])
            }
            if case .array(let items) = value, shape.has("items") {
                for (position, item) in items.enumerated() { try walk(item, shape["items"], path + [.index(position)]) }
            }
            for branchKey in ["oneOf", "anyOf", "allOf"] {
                for branch in shape[branchKey].list { try walk(value, branch, path) }
            }
        }
        try walk(value, types[rootType], [])
    }
    static func checkInterpretationComplete(_ payload: J) throws {
        let (_, _, kinds, _) = try definitionContract()
        let staticPolicyCarrier = try SemanticContract.loadedContract.get()["static_policy"]["definition"]["carrier"]["id"].text
        try visitExtensions(payload) { extensionValue, _ in
            if extensionValue["critical"].boolean && kinds[extensionValue["id"].text] == nil && extensionValue["id"].text != staticPolicyCarrier {
                throw PublicFailure("READ_UNSUPPORTED_CRITICAL")
            }
        }
    }
    static func checkNativeMethods(_ payload: J) throws {
        let contract = try SemanticContract.loadedContract.get()
        var required: [String: J] = [:]
        for requirement in contract["component_semantics"]["definition"]["native_method_requirements"].list {
            required[requirement["term"].text] = requirement
        }
        for (index, judgment) in payload["judgments"].list.enumerated() {
            let method = judgment["method"]
            guard !method["method"]["extension"].boolean, let requirement = required[method["method"]["term"].text] else { continue }
            let missingTypes = requirement["component_types"].list.contains { type in
                !method["components"].list.contains { $0["method"]["term"].text == type.text && !$0["method"]["extension"].boolean }
            }
            let missingRoles = requirement["binding_roles"].list.contains { role in
                !method["bindings"].list.contains { $0["role"].text == role.text }
            }
            if missingTypes || missingRoles {
                throw PublicFailure("READ_CORE_INVALID", field: "/payload/judgments/\(index)/method", subject: judgment["id"].text)
            }
        }
    }
    // JS String.prototype.trim whitespace: TAB VT FF SP NBSP ZWNBSP + Zs + LF CR LS PS.
    static func jsWhitespace(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 9, 10, 11, 12, 13, 32, 160, 0xFEFF, 0x2028, 0x2029: return true
        default: return (0x2000...0x200A).contains(scalar.value) || scalar.value == 0x202F || scalar.value == 0x205F || scalar.value == 0x3000
        }
    }
    static func text(_ value: J, _ maximum: Int, _ judgment: J = nil, _ component: J = nil) throws {
        guard case .string(let text) = value, !text.isEmpty,
              Array(text.unicodeScalars).first.map({ !jsWhitespace($0) }) ?? false,
              Array(text.unicodeScalars).last.map({ !jsWhitespace($0) }) ?? false,
              scalar(text, maximum: maximum, controls: true) else { try failure("content", judgment, component) }
    }
    static func itemList(_ items: [J], _ judgment: J, _ component: J, _ discriminators: Bool, _ limits: J) throws -> Set<String> {
        if items.count > Int(limits["items_per_component"].numeric) { try failure("limit", judgment, component) }
        var keys = Set<String>()
        for item in items {
            let key = item["key"].text
            // The JS `\w` gate is implied by the ASCII key grammar; only the
            // grammar is needed (ICU's \w is Unicode-aware, JS's is ASCII).
            guard key.range(of: "^[a-z][a-z0-9-]{0,63}$", options: .regularExpression) != nil else { try failure("content", judgment, component) }
            if !keys.insert(key).inserted { try failure("content", judgment, component) }
            try text(item["title"], Int(limits["title_utf8_bytes"].numeric), judgment, component)
            try text(discriminators ? item["prompt"] : item["meaning"], Int(limits["meaning_prompt_criterion_utf8_bytes"].numeric), judgment, component)
        }
        return keys
    }
    static func plainProfile(_ type: String, _ content: J, _ judgment: J, _ component: J, _ limits: J) throws -> J {
        guard case .object = content else { try failure("content", judgment, component) }
        if case .array(let items) = content["items"], items.count > Int(limits["items_per_component"].numeric) { try failure("limit", judgment, component) }
        if type == "taxonomy", case .array(let broader) = content["broader"], broader.count > Int(limits["edges_per_component"].numeric) { try failure("limit", judgment, component) }
        if type == "discriminator-set", case .array(let items) = content["items"] {
            var edges = 0
            for item in items { edges += item["contrasts"].list.count }
            if edges > Int(limits["edges_per_component"].numeric) { try failure("limit", judgment, component) }
        }
        let schema = ["taxonomy": "TaxonomyContent", "candidate-set": "CandidateSetContent", "discriminator-set": "DiscriminatorContent"][type]!
        do { _ = try SemanticContract.validate(schema, content) } catch { try failure("content", judgment, component) }
        let keys = try itemList(content["items"].list, judgment, component, type == "discriminator-set", limits)
        if type == "taxonomy" {
            var edgeSet = Set<String>()
            var graph: [String: [String]] = [:]
            for key in keys { graph[key] = [] }
            for edge in content["broader"].list {
                let narrower = edge["narrowerKey"].text, broader = edge["broaderKey"].text
                if !keys.contains(narrower) || !keys.contains(broader) { try failure("reference", judgment, component) }
                if narrower == broader { try failure("cycle", judgment, component) }
                if !edgeSet.insert(R2Registry.canonicalKey(.array([edge["narrowerKey"], edge["broaderKey"]]))).inserted { try failure("content", judgment, component) }
                graph[narrower]!.append(broader)
            }
            var visiting = Set<String>(), longest: [String: Int] = [:]
            func depth(_ key: String, _ ancestors: Int) throws -> Int {
                if ancestors > Int(limits["taxonomy_path_edges"].numeric) { try failure("limit", judgment, component) }
                if visiting.contains(key) { try failure("cycle", judgment, component) }
                if let cached = longest[key] { return cached }
                visiting.insert(key)
                var value = 0
                for next in graph[key]! { value = max(value, 1 + (try depth(next, ancestors + 1))) }
                visiting.remove(key)
                if value > Int(limits["taxonomy_path_edges"].numeric) { try failure("limit", judgment, component) }
                longest[key] = value
                return value
            }
            for key in keys { _ = try depth(key, 0) }
            return ["kind": "taxonomy",
                    "items": .array(content["items"].list.sorted { SectionFrameGraph.utf8Less($0["key"].text, $1["key"].text) }),
                    "broader": .array(content["broader"].list.sorted {
                        SectionFrameGraph.utf8Less($0["narrowerKey"].text, $1["narrowerKey"].text) || (exact($0["narrowerKey"].text, $1["narrowerKey"].text) && SectionFrameGraph.utf8Less($0["broaderKey"].text, $1["broaderKey"].text))
                    })]
        }
        if type == "candidate-set" { return ["kind": .string(type), "items": .array(content["items"].list.sorted { SectionFrameGraph.utf8Less($0["key"].text, $1["key"].text) })] }
        // Target-dependent discriminator validation follows after all declarations.
        for item in content["items"].list {
            var candidates = Set<String>()
            for contrast in item["contrasts"].list {
                if !candidates.insert(contrast["candidateKey"].text).inserted { try failure("content", judgment, component) }
                try text(contrast["criterion"], Int(limits["meaning_prompt_criterion_utf8_bytes"].numeric), judgment, component)
            }
        }
        return .null
    }
    static func resolveComponents(_ payload: J) throws -> [String: J] {
        let (definition, digest, kinds, profiles) = try definitionContract()
        let limits = definition["limits"]
        var byJudgment: [String: J] = [:]
        for judgment in payload["judgments"].list { byJudgment[judgment["id"].text] = judgment }
        var selected = R2Registry.OrderedMap<J>()          // component id -> { value, body, owner }
        var presences: [String: J] = [:]
        var allValues: [J] = []
        var aggregate: J? = nil
        var totalBytes = 0
        let componentCount = payload["judgments"].list.reduce(0) { $0 + $1["method"]["components"].list.count }
        if componentCount > Int(limits["components_per_payload"].numeric) { try failure("limit") }
        for judgment in payload["judgments"].list where judgment["method"] != .null {
            presences[judgment["id"].text] = ["components_state": "declared", "bindings_state": "declared"]
        }
        var seenPresence = Set<String>()
        try visitExtensions(payload) { extensionValue, path in
            guard let registered = kinds[extensionValue["id"].text] else { return }
            let judgmentPosition = path.count == 4 && path[0] == .key("judgments") && path[2] == .key("extensions")
            let payloadPosition = path.count == 2 && path[0] == .key("extensions")
            var judgment: J = nil
            if judgmentPosition, case .index(let position) = path[1] { judgment = payload["judgments"].list[position] }
            let kind = registered["kind"].text
            let errorKind = kind == "component" ? "declaration" : kind
            let inRightPosition = kind == "adoption" ? payloadPosition : judgmentPosition
            if !extensionValue["critical"].boolean || !exact(extensionValue["definition"].text, registered["definition"].text) || !inRightPosition {
                try failure(errorKind, judgment["id"])
            }
            let value = try jsonValue(extensionValue["value"], errorKind, judgment["id"])
            guard case .object = value else { try failure(errorKind, judgment["id"]) }
            if kind == "presence" {
                do { _ = try SemanticContract.validate("MethodPresenceCarrier", value) } catch { try failure("presence", judgment["id"]) }
                if judgment["method"] == .null || !exact(value["judgment_ref"].text, judgment["id"].text) || seenPresence.contains(judgment["id"].text)
                    || (value["components_state"].text == "declared" && value["bindings_state"].text == "declared") { try failure("presence", judgment["id"]) }
                if (value["components_state"].text == "undeclared" && !judgment["method"]["components"].list.isEmpty)
                    || (value["bindings_state"].text == "undeclared" && !judgment["method"]["bindings"].list.isEmpty) { try failure("presence", judgment["id"]) }
                seenPresence.insert(judgment["id"].text)
                presences[judgment["id"].text] = ["components_state": value["components_state"], "bindings_state": value["bindings_state"]]
                return
            }
            if kind == "adoption" {
                do { _ = try SemanticContract.validate("ComponentAdoptionCarrier", value) } catch { try failure("adoption") }
                if aggregate != nil { try failure("adoption") }
                aggregate = value
                return
            }
            if judgment["method"] == .null || !exact(value["judgment_ref"].text, judgment["id"].text) { try failure("reference", judgment["id"]) }
            guard let component = judgment["method"]["components"].list.first(where: { exact($0["id"].text, value["component_ref"].text) }) else {
                try failure("reference", judgment["id"])
            }
            let componentId = component["id"].text, profile = profiles[value["component_type"].text]
            if selected.get(componentId) != nil || component["method"]["extension"].boolean || profile == nil
                || !exact(value["profile_id"].text, profile!) || !exact(value["contract_id"].text, definition["id"].text)
                || !exact(value["contract_version"].text, definition["version"].text) || !exact(value["definition_digest"].text, digest) {
                try failure("declaration", judgment["id"], .string(componentId))
            }
            var bytes: Int
            do { bytes = try KDNAJSON.canonical(value["content"]).count } catch { try failure("content", judgment["id"], .string(componentId)) }
            // JS utf8() applies the 1 MiB author cap before the component limit.
            if bytes > 1048576 { try failure("content", judgment["id"], .string(componentId)) }
            totalBytes += bytes
            if bytes > Int(limits["content_canonical_bytes"].numeric) || totalBytes > Int(limits["opted_in_total_canonical_bytes"].numeric) { try failure("limit", judgment["id"], .string(componentId)) }
            let body = try plainProfile(value["component_type"].text, value["content"], judgment["id"], .string(componentId), limits)
            do { _ = try SemanticContract.validate("ComponentSemanticsCarrier", value) } catch { try failure("declaration", judgment["id"], .string(componentId)) }
            if !exact(value["content_digest"].text, sha(try KDNAJSON.canonical(value["content"]))) { try failure("binding", judgment["id"], .string(componentId)) }
            if value["statement_origin"].text == "mechanical_content_representation" {
                let statement = (try? String(decoding: KDNAJSON.canonical(value["content"]), as: UTF8.self)) ?? ""
                if !exact(component["statement"].text, statement) { try failure("declaration", judgment["id"], .string(componentId)) }
            }
            let declarationDigest = sha(try KDNAJSON.canonical(["component": component, "statement_origin": value["statement_origin"]]))
            if !exact(value["component_declaration_digest"].text, declarationDigest) { try failure("binding", judgment["id"], .string(componentId)) }
            var bindings = judgment["method"]["bindings"].list.filter { exact($0["component_ref"].text, componentId) }
            if bindings.contains(where: { $0.has("target") }) { try failure("binding", judgment["id"], .string(componentId)) }
            bindings.sort {
                let left = $0["role"].text, right = $1["role"].text
                return SectionFrameGraph.utf8Less(left, right) || (exact(left, right) && SectionFrameGraph.utf8Less($0["target_ref"].text, $1["target_ref"].text))
            }
            var seenBindings = Set<String>()
            for binding in bindings {
                if !exact(binding["target_ref"].text, judgment["id"].text) || !seenBindings.insert(R2Registry.canonicalKey(binding)).inserted { try failure("binding", judgment["id"], .string(componentId)) }
            }
            if !exact(value["bindings_digest"].text, sha(try KDNAJSON.canonical(.array(bindings)))) { try failure("binding", judgment["id"], .string(componentId)) }
            selected.set(componentId, ["value": value, "body": body, "owner": judgment["id"]])
            allValues.append(value)
        }
        for (componentId, entry) in selected.entries {
            let value = entry["value"]
            if value["component_type"].text != "discriminator-set" { continue }
            let judgment = entry["owner"]
            guard let target = selected.get(value["content"]["candidateSetRef"].text), exact(target["owner"].text, judgment.text), target["value"]["component_type"].text == "candidate-set" else {
                try failure("reference", judgment, .string(componentId))
            }
            let keys = Set(target["value"]["content"]["items"].list.map { $0["key"].text })
            for item in value["content"]["items"].list {
                for contrast in item["contrasts"].list where !keys.contains(contrast["candidateKey"].text) { try failure("reference", judgment, .string(componentId)) }
            }
            var updated = entry
            updated["body"] = ["kind": "discriminator-set", "candidateSetRef": value["content"]["candidateSetRef"],
                               "candidateIndex": .array(target["body"]["items"].list.map { ["key": $0["key"], "title": $0["title"]] }),
                               "items": .array(value["content"]["items"].list.sorted { SectionFrameGraph.utf8Less($0["key"].text, $1["key"].text) }.map { item -> J in
                                   var updated = item
                                   updated["contrasts"] = .array(item["contrasts"].list.sorted { SectionFrameGraph.utf8Less($0["candidateKey"].text, $1["candidateKey"].text) })
                                   return updated
                               })]
            selected.set(componentId, updated)
        }
        if (aggregate != nil) != (selected.keys.count > 0) { try failure("adoption") }
        if let aggregate {
            allValues.sort {
                SectionFrameGraph.utf8Less($0["judgment_ref"].text, $1["judgment_ref"].text)
                    || (exact($0["judgment_ref"].text, $1["judgment_ref"].text) && SectionFrameGraph.utf8Less($0["component_ref"].text, $1["component_ref"].text))
            }
            var proposalSet = Set<String>()
            var proposals: [String] = []
            for value in allValues { if proposalSet.insert(value["adoption_proposal_digest"].text).inserted { proposals.append(value["adoption_proposal_digest"].text) } }
            proposals.sort(by: SectionFrameGraph.utf8Less)
            let declarationSet = sha(try KDNAJSON.canonical(.array(allValues)))
            let proposalSetDigest = sha(try KDNAJSON.canonical(.array(proposals.map { .string($0) })))
            if !exact(aggregate["contract_id"].text, definition["id"].text) || !exact(aggregate["contract_version"].text, definition["version"].text)
                || !exact(aggregate["definition_digest"].text, digest)
                || !exact(aggregate["declaration_set_digest"].text, declarationSet)
                || !exact(aggregate["proposal_set_digest"].text, proposalSetDigest) { try failure("adoption") }
        }
        for judgment in payload["judgments"].list {
            for binding in judgment["method"]["bindings"].list where binding.has("target_ref") && selected.get(binding["component_ref"].text) == nil {
                try failure("binding", judgment["id"], binding["component_ref"])
            }
        }
        var methods: [String: J] = [:]
        for judgment in payload["judgments"].list {
            if judgment["method"] == .null { continue }
            let id = judgment["id"].text
            var entries: [J] = []
            for component in judgment["method"]["components"].list {
                let entry = selected.get(component["id"].text)
                let common: J = ["judgment_ref": .string(id), "component_ref": component["id"],
                                 "component_type": entry?["value"]["component_type"] ?? .null, "definition_digest": .string(digest)]
                if let entry {
                    let value = entry["value"]
                    var row = common
                    row["status"] = "supported"
                    row["declaration_digest"] = .string(sha(try KDNAJSON.canonical(value)))
                    row["content_digest"] = value["content_digest"]
                    row["profile_id"] = value["profile_id"]
                    row["component_declaration_digest"] = value["component_declaration_digest"]
                    row["statement_origin"] = value["statement_origin"]
                    row["bindings_digest"] = value["bindings_digest"]
                    row["adoption_proposal_digest"] = value["adoption_proposal_digest"]
                    row["authored_content"] = value["content"]
                    row["body"] = entry["body"]
                    entries.append(row)
                } else {
                    var row = common
                    row["status"] = "undeclared"
                    row["declaration_digest"] = nil
                    row["content_digest"] = nil
                    row["profile_id"] = nil
                    row["component_declaration_digest"] = nil
                    row["statement_origin"] = nil
                    row["bindings_digest"] = nil
                    row["adoption_proposal_digest"] = nil
                    row["authored_content"] = nil
                    row["body"] = nil
                    entries.append(row)
                }
            }
            methods[id] = ["declaration": judgment["method"], "declaration_presence": presences[id] ?? .null, "component_interpretations": .array(entries)]
        }
        return methods
    }
}
