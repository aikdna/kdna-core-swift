import Foundation

// The 0.5-generation canonical IR (canonical-ir.js, @aikdna/kdna-core@0.36.0):
// buildIR derives the whole IR graph from the validated registry — role
// naming, stable identity ids, reference meanings, catalog, mandatory
// closures, the global asset closure, display index and expansion targets —
// then validates it as CanonicalIR and checks interpretation completeness.
//
// The released `visit` callback pair also walks the manifest for extension
// carriers; Manifest06Candidate has no extension positions, so the payload
// walks are equivalent here (recorded; the manifest walk can be added if a
// future manifest grows one).
enum CanonicalIR {
    static let roles: [String: String] = ["asset": "asset_declaration", "contract": "result_contract", "component": "method_component",
                                          "unit": "method_unit", "plan": "method_plan", "plan_node": "method_instance",
                                          "policy": "conditional_policy", "branch_entry": "branch"]
    static func stableId(_ asset: J, _ role: String, _ identity: J) -> String {
        let digest = sha((try? KDNAJSON.canonical(.array([asset, identity]))) ?? Data())
        return role + ":" + String(digest.dropFirst(7).prefix(40))
    }
    static func buildIR(_ manifest: J, _ payload: J, _ entries: [KDNAKey: Data]) throws -> J {
        let contract = try SemanticContract.loadedContract.get()
        let registry = try R2Semantics.validateR2(manifest, payload, entries)
        let methodValues = try ComponentSemantics.resolveComponents(payload)
        let policyValues = try StaticPolicySemantics.resolveStaticPolicies(payload) { judgment, candidate in
            var merged = judgment
            merged["result"] = ["contract_ref": judgment["result_contract"]["id"], "result_type": candidate["result_type"], "value": candidate["value"]]
            _ = try R2Values.validateResult(merged)
        }
        var assetValue: J = [:]
        for name in ["asset_id", "asset_type", "asset_uid", "version", "judgment_version", "title", "summary", "languages", "created_at", "updated_at", "creator", "license", "access", "description", "keywords", "lineage", "encryption", "entitlement"] where manifest.has(name) {
            assetValue[name] = manifest[name]
        }
        for name in ["scope", "kernel", "reading_order", "cohesion", "attributions", "content_risk", "extensions"] where payload.has(name) {
            assetValue[name] = payload[name]
        }
        assetValue["history"] = ["coverage": manifest["history"]["coverage"], "statement": manifest["history"]["statement"]]
        var declarations: J = ["highest_question": payload["declarations"]["highest_question"]]
        if payload["declarations"]["boundaries"] != .null {
            declarations["boundaries"] = ["state": payload["declarations"]["boundaries"]["state"]]
        }
        assetValue["declarations"] = declarations
        registry.setValue(registry.identity(registry.asset), assetValue)
        var nodes: [J] = [], nodeMap: [String: J] = [:]
        var references: [J] = []
        for record in registry.ordered {
            let role = record.value["kind"].text == "emission_list" && record.target["kind"].text == "contract"
                ? "emission_list_contract"
                : (roles[record.target["kind"].text] ?? record.target["kind"].text)
            var node: J = ["id": .string(stableId(payload["asset"], role, record.target)), "role": .string(role),
                           "target": record.target, "owner": record.owner, "owner_judgment_id": record.judgment,
                           "value": record.value]
            if record.activation != .null { node["activation"] = record.activation }
            if record.target["kind"].text == "judgment" {
                node["method_interpretation"] = methodValues[record.target["id"].text] ?? .null
                if let policy = policyValues[record.target["id"].text] { node["static_policy_interpretation"] = policy }
            }
            nodes.append(node)
            nodeMap[registry.identity(record.target)] = node
        }
        func nodeFor(_ target: J) -> J { nodeMap[registry.identity(target)]! }
        for record in registry.ordered {
            for (targetKey, rolesValue) in registry.referenceRoles[registry.identity(record.target)]!.entries {
                let from = nodeFor(record.target), to = nodeMap[targetKey]!
                if from["id"] == to["id"] { continue }
                var meanings: [J] = []
                for (declaredKey, mandatory) in rolesValue.entries {
                    let declaredRole: J = declaredKey.isEmpty ? .null : .string(declaredKey)
                    meanings.append(["declared_role": declaredRole, "mandatory": .bool(mandatory),
                                     "role": declaredKey.isEmpty ? .string(mandatory ? "mandatory_support" : "optional_expansion") : .string(declaredKey)])
                }
                meanings.sort { SectionFrameGraph.utf8Less($0["role"].text, $1["role"].text) }
                for meaning in meanings {
                    var identityParts: [J] = [record.target, to["target"], meaning["mandatory"]]
                    if meaning["declared_role"] != .null { identityParts.append(meaning["declared_role"]) }
                    let identity: J = .array(identityParts)
                    references.append(["id": .string(stableId(payload["asset"], "reference", identity)),
                                       "source_node": from["id"], "target_node": to["id"],
                                       "role": meaning["role"], "mandatory": meaning["mandatory"]])
                }
            }
        }
        func selection(_ id: String) -> J { ["asset_id": payload["asset"]["asset_id"], "asset_version": payload["asset"]["asset_version"], "judgment_id": .string(id)] }
        var catalog: [J] = [], mandatoryClosures: [J] = []
        for judgment in payload["judgments"].list {
            var row: J = ["judgment_id": judgment["id"], "focus": judgment["focus"],
                          "node_ref": nodeFor(R2Registry.ref("judgment", judgment["id"].text))["id"], "parent_ref": judgment["parent_ref"]]
            if judgment["lifecycle"] != .null { row["lifecycle"] = judgment["lifecycle"] }
            catalog.append(row)
            let closure = try R2Registry.closure(registry, [registry.asset, R2Registry.ref("judgment", judgment["id"].text)])
            mandatoryClosures.append(["selection": selection(judgment["id"].text), "node_ids": .array(closure.map { nodeFor($0.target)["id"] })])
        }
        var globalSeeds: [J] = [registry.asset]
        globalSeeds.append(contentsOf: payload["relationships"].list.map { R2Registry.ref("relationship", $0["id"].text) })
        globalSeeds.append(contentsOf: payload["dependencies"].list.map { R2Registry.ref("dependency", $0["id"].text) })
        var globalClosureSeeds: [J] = [registry.asset]
        globalClosureSeeds.append(contentsOf: R2Registry.values(payload["declarations"]["boundaries"]).map { R2Registry.ref("boundary", $0["id"].text) })
        let globalRecords = try R2Registry.closure(registry, globalClosureSeeds)
        var globalIds = Set(globalRecords.map { nodeFor($0.target)["id"].text })
        for target in globalSeeds { globalIds.insert(nodeFor(target)["id"].text) }
        let assetClosure = nodes.filter { globalIds.contains($0["id"].text) }.map { $0["id"] }
        func display(_ record: R2Registry.Record) -> J {
            let v = record.value, kind = record.target["kind"].text
            if kind == "judgment" { return v["focus"] }
            if kind == "asset" { return v["title"] }
            if kind == "material" && v["kind"].text == "definition" { return v["term"] }
            if kind == "example" { return v["title"] }
            if v.has("name") { return v["name"] }
            if v.has("role") { return v["role"] }
            return .string(kind + ":" + record.target["id"].text)
        }
        var assetIndex: [J] = []
        for record in registry.ordered {
            assetIndex.append(["target": record.target, "owner": record.owner, "display_name": display(record), "node_ref": nodeFor(record.target)["id"]])
        }
        var expansionTargets: [J] = []
        func scopeFor(_ seeds: [J]) throws -> J { .array(try R2Registry.closure(registry, seeds).map { nodeFor($0.target)["id"] }) }
        for record in registry.ordered {
            expansionTargets.append(["anchor": ["kind": "asset"], "target": record.target, "scope": try scopeFor([registry.asset, record.target])])
        }
        for judgment in payload["judgments"].list {
            let seeds = [registry.asset, R2Registry.ref("judgment", judgment["id"].text)]
            let mandatory = try R2Registry.closure(registry, seeds)
            var available = Set(mandatory.map { registry.identity($0.target) })
            for record in mandatory where record.target["kind"].text != "asset" {
                for (targetKey, _) in registry.edges[registry.identity(record.target)]!.entries { available.insert(targetKey) }
            }
            for record in registry.ordered where available.contains(registry.identity(record.target)) {
                expansionTargets.append(["anchor": ["kind": "judgment", "selection": selection(judgment["id"].text)], "target": record.target, "scope": try scopeFor(seeds + [record.target])])
            }
        }
        let tuple = contract["versionTuple"]
        var unresolved: [J] = []
        for entry in registry.unresolved { unresolved.append(["source": entry.source, "target": entry.target, "mandatory": .bool(entry.mandatory)]) }
        let ir: J = ["contract": tuple["ir"], "tuple": tuple, "asset": payload["asset"], "nodes": .array(nodes), "catalog": .array(catalog),
                     "references": .array(references), "relationships": payload["relationships"], "mandatory_closures": .array(mandatoryClosures),
                     "expansion_targets": .array(expansionTargets), "asset_closure": .array(assetClosure), "asset_index": .array(assetIndex),
                     "unresolved_external": .array(unresolved)]
        _ = try SemanticContract.validate("CanonicalIR", ir)
        try ComponentSemantics.checkInterpretationComplete(payload)
        return ir
    }
}
