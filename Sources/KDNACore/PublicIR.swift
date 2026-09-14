import Foundation

enum PublicIR {
    static func unique(_ items: [J], key: String = "id") throws -> [KDNAKey:J] {
        var result: [KDNAKey:J] = [:]
        for item in items { let id = KDNAKey(item[key].text); try demand(result[id] == nil); result[id] = item }
        return result
    }
    static func provided(_ value: J) -> [J] { value["state"] == "provided" ? value["value"].list : [] }
    static func bounds(_ shape: J) throws { try demand(shape["maximum"] == .null || shape["maximum"].numeric >= shape["minimum"].numeric) }
    static func validateShape(_ shape: J) throws {
        if shape["kind"] == "list" { try bounds(shape); try validateShape(shape["item_shape"]) }
        if shape["kind"] == "record" { _ = try unique(shape["fields"].list, key: "name"); for field in shape["fields"].list { try validateShape(field["shape"]) } }
    }
    static func resultShape(_ shape: J, _ value: J) throws {
        if shape["kind"] == "scalar" { try demand(value["kind"] == shape["scalar_type"]); return }
        if shape["kind"] == "list" {
            try bounds(shape)
            try demand(value["kind"] == "list" && Double(value["items"].list.count) >= shape["minimum"].numeric && (shape["maximum"] == .null || Double(value["items"].list.count) <= shape["maximum"].numeric))
            for item in value["items"].list { try resultShape(shape["item_shape"], item) }; return
        }
        try demand(value["kind"] == "record")
        let fields = try unique(shape["fields"].list, key: "name"), actual = try unique(value["fields"].list, key: "name")
        for (key, field) in fields where field["required"].boolean { try demand(actual[key] != nil) }
        for (key, field) in actual { guard let expected = fields[key] else { throw PublicFailure() }; try resultShape(expected["shape"], field["value"]) }
    }
    static func build(_ manifest: J, _ payload: J, _ entries: [KDNAKey:Data], _ contract: J) throws -> J {
        var definitions: [KDNAKey:(String,J)] = [:]
        var nodes: [J] = [], references: [J] = [], catalog: [J] = []
        var ownNodes: [KDNAKey:[J]] = [:], sourceNodes: [KDNAKey:J] = [:]
        let judgments = payload["judgments"].list
        let kinds = [("actor","actors"),("judgment","judgments"),("reason","reasons"),("source","sources"),("source_use","source_uses"),("resource","resources"),("material","materials"),("relationship","relationships"),("dependency","dependencies")]
        func register(_ kind: String, _ items: [J]) throws {
            for (key, item) in try unique(items) { try demand(definitions[key] == nil); definitions[key] = (kind,item) }
        }
        for (kind, key) in kinds { try register(kind, payload[key].list) }
        try register("result_contract", judgments.map { $0["result_contract"] })
        try register("method_component", judgments.flatMap { $0["method"]["components"].list })
        try register("boundary", provided(payload["declarations"]["boundaries"]) + judgments.flatMap { provided($0["boundaries"]) })
        try register("exception", judgments.flatMap { provided($0["exceptions"]) })
        try register("misuse", judgments.flatMap { provided($0["misuse"]) })
        func require(_ id: J, _ kind: String? = nil) throws -> J {
            guard let d = definitions[KDNAKey(id.text)], kind == nil || d.0 == kind else { throw PublicFailure() }; return d.1
        }
        for j in judgments {
            let c = j["result_contract"]
            try bounds(c); try validateShape(c["shape"])
            if j.has("result") {
                let r = j["result"]
                try demand(r["contract_ref"] == c["id"] && c["allowed_result_types"].list.contains(r["result_type"]))
                try resultShape(c["shape"], r["value"])
                let count = r["value"]["kind"] == "list" ? Double(r["value"]["items"].list.count) : 1
                try demand(count >= c["minimum"].numeric && (c["maximum"] == .null || count <= c["maximum"].numeric))
            }
            if j.has("formation_rule") { try demand(j["formation_rule"]["output_contract_ref"] == c["id"]) }
            for id in j["subject"]["actor_ids"].list { _ = try require(id, "actor") }
            for id in j["reason_refs"].list { try demand(require(id, "reason")["judgment_ref"] == j["id"]) }
            for id in j["material_refs"].list { _ = try require(id, "material") }
            if j.has("method") {
                let components = try unique(j["method"]["components"].list)
                for binding in j["method"]["bindings"].list { try demand(components[KDNAKey(binding["component_ref"].text)] != nil); _ = try require(binding["target_ref"]) }
            }
            for condition in j["formation_rule"]["conditions"].list {
                let c = condition["kind"] == "external_evaluator" ? condition["declaration"] : condition
                if c["kind"] == "structured" { for operand in c["operands"].list where operand["kind"] == "dependency" { try demand(require(operand["dependency_ref"], "dependency")["consumer_judgment_ref"] == j["id"]) } }
            }
            for e in provided(j["exceptions"]) where e["boundary_ref"] != .null { _ = try require(e["boundary_ref"], "boundary") }
        }
        for reason in payload["reasons"].list { _ = try require(reason["judgment_ref"], "judgment"); for id in reason["component_refs"].list { _ = try require(id, "method_component") } }
        for boundary in [payload["declarations"]["boundaries"]] + judgments.map({ $0["boundaries"] }) { for b in provided(boundary) { _ = try require(b["declared_by"], "actor") } }
        for claim in provided(payload["attributions"]) { for id in claim["actor_ids"].list { _ = try require(id, "actor") } }
        for material in payload["materials"].list {
            if material["resource_ref"] != .null && !material["resource_ref"].text.isEmpty { _ = try require(material["resource_ref"], "resource") }
            for id in material["source_refs"].list { _ = try require(id, "source") }
        }
        for resource in payload["resources"].list { guard let bytes = entries[KDNAKey(resource["entry"].text)] else { throw PublicFailure() }; try demand(sha(bytes) == resource["digest"].text) }
        for use in payload["source_uses"].list { _ = try require(use["source_ref"], "source"); _ = try require(use["target_ref"], use["target_kind"].text) }
        for relationship in payload["relationships"].list { for p in relationship["participants"].list { _ = try require(p["judgment_ref"], "judgment") } }
        for dependency in payload["dependencies"].list {
            _ = try require(dependency["consumer_judgment_ref"], "judgment")
            let p = dependency["producer"]
            if p["kind"] == "judgment_result" { try demand(require(p["judgment_ref"], "judgment")["result_contract"]["id"] == p["result_contract_ref"]) }
            else { _ = try require(p["source_ref"], "source") }
        }
        let methods = try PublicComponents.resolve(payload, contract)
        func nodeId(_ role: String, _ identity: String) throws -> J { .string(role + ":" + sha(try KDNAJSON.canonical([payload["asset"], .string(identity)])).dropFirst(7).prefix(40)) }
        func node(_ role: String, _ identity: String, _ value: J, _ owner: J = nil) throws -> J {
            let item: J = ["id": try nodeId(role, identity), "role": .string(role), "owner_judgment_id": owner, "value": value]
            nodes.append(item)
            if owner != .null { ownNodes[KDNAKey(owner.text), default: []].append(item["id"]) }
            return item
        }
        var declaration: J = [:]
        for key in ["title","creator","license","summary","description","language","access"] where manifest.has(key) { declaration[key] = manifest[key] }
        for key in ["content_risk","extensions"] where payload.has(key) { declaration[key] = payload[key] }
        _ = try node("asset_declaration", "asset", declaration); _ = try node("scope", "asset-scope", payload["scope"])
        for (key, role, identity) in [("declarations","declaration","authored-declarations"),("cohesion","cohesion","cohesion"),("attributions","attribution","attributions")] where payload.has(key) { _ = try node(role, identity, payload[key]) }
        for (kind, key) in kinds where kind != "judgment" { for value in payload[key].list { sourceNodes[KDNAKey(value["id"].text)] = try node(kind, value["id"].text, value) } }
        for j in judgments {
            let id = j["id"], main = try node("judgment", j["id"].text, j, j["id"])
            sourceNodes[KDNAKey(id.text)] = main
            catalog.append(["judgment_id": id, "label": j.has("label") ? j["label"] : j["focus"], "node_ref": main["id"]])
            _ = try node("subject", id.text, j["subject"], id); _ = try node("scope", id.text, j["scope"], id)
            let c = j["result_contract"]; sourceNodes[KDNAKey(c["id"].text)] = try node("result_contract", c["id"].text, c, id)
            for key in ["result","formation_rule"] where j.has(key) { _ = try node(key, id.text, j[key], id) }
            if j.has("method") { let n = try node("method", id.text, methods[KDNAKey(id.text)]!, id); for c in j["method"]["components"].list { sourceNodes[KDNAKey(c["id"].text)] = n } }
            for (key, role) in [("boundaries","boundary"),("exceptions","exception"),("misuse","misuse")] { for (i, value) in provided(j[key]).enumerated() { sourceNodes[KDNAKey(value["id"].text)] = try node(role, id.text + ":" + String(i), value, id) } }
        }
        let assetIds = nodes.filter { $0["owner_judgment_id"] == .null && ["asset_declaration","declaration","scope","cohesion","attribution"].contains($0["role"].text) }.map { KDNAKey($0["id"].text) }
        let declarationNode = nodes.first { $0["role"] == "declaration" && $0["owner_judgment_id"] == .null }
        for b in provided(payload["declarations"]["boundaries"]) { sourceNodes[KDNAKey(b["id"].text)] = declarationNode }
        func closedIds(_ judgment: J, _ extra: J = nil) throws -> [J] {
            var selected = Set(assetIds), visited: Set<KDNAKey> = []
            func add(_ id: J) throws {
                let key = KDNAKey(id.text)
                if visited.contains(key) { return }; visited.insert(key)
                guard let (kind, r) = definitions[key], let n = sourceNodes[key] else { throw PublicFailure() }
                selected.insert(KDNAKey(n["id"].text))
                if kind == "judgment" {
                    for own in ownNodes[key] ?? [] { selected.insert(KDNAKey(own.text)) }
                    for ref in r["subject"]["actor_ids"].list + r["reason_refs"].list + r["material_refs"].list { try add(ref) }
                    try add(r["result_contract"]["id"])
                    for c in r["method"]["components"].list { try add(c["id"]) }
                    for k in ["boundaries","exceptions","misuse"] { for d in provided(r[k]) { try add(d["id"]) } }
                    for b in r["method"]["bindings"].list { try add(b["target_ref"]) }
                    for condition in r["formation_rule"]["conditions"].list {
                        let c = condition["kind"] == "external_evaluator" ? condition["declaration"] : condition
                        for operand in c["operands"].list where operand["kind"] == "dependency" { try add(operand["dependency_ref"]) }
                    }
                    for d in payload["dependencies"].list where d["consumer_judgment_ref"] == id && d["required"].boolean { try add(d["id"]) }
                    for relation in payload["relationships"].list where relation["participants"].list.contains(where: { $0["judgment_ref"] == id }) { try add(relation["id"]) }
                } else if kind == "reason" {
                    try add(r["judgment_ref"]); for ref in r["component_refs"].list { try add(ref) }
                } else if kind == "material" {
                    if r["resource_ref"] != .null && !r["resource_ref"].text.isEmpty { try add(r["resource_ref"]) }; for ref in r["source_refs"].list { try add(ref) }
                } else if kind == "method_component" || kind == "result_contract" {
                    if n["owner_judgment_id"] != .null { try add(n["owner_judgment_id"]) }
                } else if kind == "source_use" { try add(r["source_ref"]); try add(r["target_ref"])
                } else if kind == "dependency" { try add(r["consumer_judgment_ref"]); try add(r["producer"][r["producer"]["kind"] == "judgment_result" ? "judgment_ref" : "source_ref"])
                } else if kind == "relationship" { for p in r["participants"].list { try add(p["judgment_ref"]) }
                } else if kind == "boundary" { try add(r["declared_by"])
                } else if kind == "exception" && r["boundary_ref"] != .null { try add(r["boundary_ref"]) }
                for use in payload["source_uses"].list where use["target_ref"] == id { try add(use["id"]) }
            }
            for b in provided(payload["declarations"]["boundaries"]) { try add(b["declared_by"]) }
            for claim in provided(payload["attributions"]) { for actor in claim["actor_ids"].list { try add(actor) } }
            try add(judgment); if extra != .null { try add(extra) }
            return nodes.filter { selected.contains(KDNAKey($0["id"].text)) }.map { $0["id"] }
        }
        func selection(_ id: J) -> J { ["asset_id": payload["asset"]["asset_id"], "asset_version": payload["asset"]["asset_version"], "judgment_id": id] }
        func reference(_ source: J, _ target: J, _ mandatory: Bool, _ role: String = "mandatory_support") throws {
            try demand(contract["types"]["ReferenceRole"]["enum"].list.contains(.string(role)))
            references.append(["id": try nodeId("reference", source.text + "\0" + target.text + "\0" + role), "source_node": source, "target_node": target, "role": .string(role), "mandatory": .bool(mandatory)])
        }
        let closures: [J] = try judgments.map { ["selection": selection($0["id"]), "node_ids": .array(try closedIds($0["id"]))] }
        for c in closures {
            guard let source = sourceNodes[KDNAKey(c["selection"]["judgment_id"].text)]?["id"] else { throw PublicFailure() }
            for id in c["node_ids"].list where id != source { try reference(source, id, true) }
        }
        let targets: [J] = try payload["dependencies"].list.filter { !$0["required"].boolean }.map { d in
            guard let target = sourceNodes[KDNAKey(d["id"].text)]?["id"] else { throw PublicFailure() }
            return ["selection": selection(d["consumer_judgment_ref"]), "target": target, "scope": .array(try closedIds(d["consumer_judgment_ref"], d["id"]))]
        }
        for target in targets {
            guard let source = sourceNodes[KDNAKey(target["selection"]["judgment_id"].text)]?["id"] else { throw PublicFailure() }
            try reference(source, target["target"], false, "optional_expansion")
        }
        let ir: J = ["contract": contract["versionTuple"]["ir"], "tuple": contract["versionTuple"], "asset": payload["asset"], "nodes": .array(nodes), "catalog": .array(catalog), "references": .array(references), "relationships": payload.has("relationships") ? payload["relationships"] : [], "mandatory_closures": .array(closures), "expansion_targets": .array(targets)]
        try PublicSchema.validate("CanonicalIR", ir, contract)
        return ir
    }
}
