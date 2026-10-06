import Foundation

// The scoped materialization (section-scoped-materialize.js,
// @aikdna/kdna-core@0.36.0): from the scoped registry and the observed
// registration nodes, produce the section snapshot body — the asset value
// projection (original Manifest values authoritative), the judgment catalog
// check, the reference set over the selected nodes, the asset index subset
// with its display names, the mandatory closures and the global closures.
enum SectionScopedMaterialize {
    static func same(_ a: J, _ b: J) -> Bool {
        (try? KDNAJSON.canonical(a)) == (try? KDNAJSON.canonical(b))
    }
    static func materializeScoped(_ registry: R2Registry.Registry, _ payload: J, _ manifest: J, _ nodes: [J], _ ordered: [J], _ selectedIds: [String], _ meta: J, _ loadedJudgments: Set<String>) throws -> J {
        var byKey: [String: J] = [:]
        for node in nodes { byKey[registry.identity(node["target"])] = node }
        let selected = Set(ordered.map { $0["id"].text })
        guard let asset = byKey[registry.identity(registry.asset)] else { throw PublicFailure("READ_CORE_INVALID") }
        // Same field projection as canonical-ir.buildIR; original Manifest values are authoritative here.
        var assetValue: J = [:]
        for key in ["asset_id", "asset_type", "asset_uid", "version", "judgment_version", "title", "summary", "languages", "created_at", "updated_at", "creator", "license", "access", "description", "keywords", "lineage", "encryption", "entitlement"] where manifest.has(key) {
            assetValue[key] = manifest[key]
        }
        for key in ["scope", "kernel", "reading_order", "cohesion", "attributions", "content_risk", "extensions"] where payload.has(key) {
            assetValue[key] = payload[key]
        }
        assetValue["history"] = ["coverage": manifest["history"]["coverage"], "statement": manifest["history"]["statement"]]
        assetValue["declarations"] = ["highest_question": payload["declarations"]["highest_question"]]
        if payload["declarations"]["boundaries"] != .null {
            assetValue["declarations"]["boundaries"] = ["state": payload["declarations"]["boundaries"]["state"]]
        }
        try demand(same(asset["value"], assetValue), "SECTION_ASSET_DECLARATION_MISMATCH")
        for judgment in payload["judgments"].list where loadedJudgments.contains(judgment["id"].text) {
            let node = byKey[registry.identity(R2Registry.ref("judgment", judgment["id"].text))]
            guard let node else { throw PublicFailure("SECTION_LOADED_CATALOG_MISMATCH") }
            var actual: J = ["judgment_id": judgment["id"], "focus": judgment["focus"], "node_ref": node["id"], "parent_ref": judgment["parent_ref"]]
            if judgment.has("lifecycle") { actual["lifecycle"] = judgment["lifecycle"] }
            guard let declared = meta["catalog"].list.first(where: { $0["judgment_id"].text == judgment["id"].text }),
                  same(declared, actual) else { throw PublicFailure("SECTION_LOADED_CATALOG_MISMATCH") }
        }
        var references: [J] = []
        for record in registry.ordered {
            guard let from = byKey[registry.identity(record.target)], selected.contains(from["id"].text) else { continue }
            guard let roles = registry.referenceRoles[registry.identity(record.target)] else { continue }
            for (targetKey, declaredRoles) in roles.entries {
                guard let to = byKey[targetKey], to["id"].text != from["id"].text, selected.contains(to["id"].text) else { continue }
                var meanings: [(declaredRole: String?, mandatory: Bool, role: String)] = []
                for (roleKey, mandatory) in declaredRoles.entries {
                    // The registry stores a null reference role as "".
                    let declaredRole: String? = roleKey.isEmpty ? nil : roleKey
                    meanings.append((declaredRole, mandatory, declaredRole ?? (mandatory ? "mandatory_support" : "optional_expansion")))
                }
                meanings.sort { SectionFrameGraph.utf8Less($0.role, $1.role) }
                for meaning in meanings {
                    var identity: [J] = [record.target, to["target"], .bool(meaning.mandatory)]
                    if let declaredRole = meaning.declaredRole { identity.append(.string(declaredRole)) }
                    let digest = sha(try KDNAJSON.canonical(.array([payload["asset"], .array(identity)])))
                    references.append(["id": .string("reference:" + String(digest.dropFirst(7).prefix(40))),
                                       "source_node": from["id"], "target_node": to["id"],
                                       "role": .string(meaning.role), "mandatory": .bool(meaning.mandatory)])
                }
            }
        }
        var available = Set(ordered.map { registry.identity($0["target"]) })
        for node in ordered where node["target"]["kind"].text != "asset" {
            if let edges = registry.edges[registry.identity(node["target"])] {
                for (key, _) in edges.entries { available.insert(key) }
            }
        }
        var metadataIndex: [String: J] = [:]
        for row in meta["asset_index"].list { metadataIndex[registry.identity(row["target"])] = row }
        func display(_ record: R2Registry.Record) throws -> String {
            let value = record.target["kind"].text == "asset" ? assetValue : try record.checkedValue()
            if record.target["kind"].text == "judgment" { return value["focus"].text }
            if record.target["kind"].text == "asset" { return value["title"].text }
            if record.target["kind"].text == "material" && value["kind"].text == "definition" { return value["term"].text }
            if record.target["kind"].text == "example" { return value["title"].text }
            if !value["name"].text.isEmpty { return value["name"].text }
            if !value["role"].text.isEmpty { return value["role"].text }
            return record.target["kind"].text + ":" + record.target["id"].text
        }
        var assetIndex: [J] = []
        for record in registry.ordered {
            let key = registry.identity(record.target)
            guard let node = byKey[key], available.contains(key), !(record.target["kind"].text == "judgment" && !selected.contains(node["id"].text)) else { continue }
            guard let row = metadataIndex[key], same(row["target"], record.target), same(row["owner"], record.owner), row["node_ref"].text == node["id"].text else {
                throw PublicFailure("SECTION_INDEX_RECORD_MISMATCH")
            }
            if record.judgment == .null || loadedJudgments.contains(record.judgment.text) {
                try demand(row["display_name"].text == (try display(record)), "SECTION_LOADED_INDEX_MISMATCH")
            }
            assetIndex.append(row)
        }
        let mandatoryClosures: [J] = try selectedIds.map { id in
            let records = try R2Registry.closure(registry, [registry.asset, R2Registry.ref("judgment", id)])
            return ["selection": ["asset_id": payload["asset"]["asset_id"], "asset_version": payload["asset"]["asset_version"], "judgment_id": .string(id)],
                    "node_ids": .array(records.map { byKey[registry.identity($0.target)]!["id"] })]
        }
        var globalIds = Set<String>()
        var globalSeeds: [J] = [registry.asset]
        for boundary in R2Registry.values(payload["declarations"]["boundaries"]) { globalSeeds.append(R2Registry.ref("boundary", boundary["id"].text)) }
        for record in try R2Registry.closure(registry, globalSeeds) { globalIds.insert(byKey[registry.identity(record.target)]!["id"].text) }
        for value in payload["relationships"].list { globalIds.insert(byKey[registry.identity(R2Registry.ref("relationship", value["id"].text))]!["id"].text) }
        for value in payload["dependencies"].list { globalIds.insert(byKey[registry.identity(R2Registry.ref("dependency", value["id"].text))]!["id"].text) }
        let relationIds = Set(ordered.filter { $0["role"].text == "relationship" }.map { $0["value"]["id"].text })
        let unresolved = registry.unresolved.filter { entry in
            guard let node = byKey[registry.identity(entry.source)] else { return false }
            return selected.contains(node["id"].text)
        }
        return ["references": .array(references),
                "relationships": .array(payload["relationships"].list.filter { relationIds.contains($0["id"].text) }),
                "asset_index": .array(assetIndex),
                "catalog": meta["catalog"],
                "mandatory_closures": .array(mandatoryClosures),
                "asset_closure": .array(nodes.filter { globalIds.contains($0["id"].text) }.map { $0["id"] }),
                "expansion_targets": .array([]),
                "unresolved_external": .array(unresolved.map { entry in ["source": entry.source, "target": entry.target, "mandatory": .bool(entry.mandatory)] })]
    }
}
