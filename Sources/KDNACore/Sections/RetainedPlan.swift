import Foundation

// The retained read plan (retained-plan.js + selected-context.generated.js,
// @aikdna/kdna-core@0.36.0): the request normalization against a snapshot
// view, the descriptor/node projection per mode with the READ_* codes, and
// the selected-context projection (asset-declaration omissions, the
// judgment catalog subset, the references/relationships closure).
enum RetainedPlan {
    static func same(_ a: J, _ b: J) -> Bool { (try? KDNAJSON.canonical(a)) == (try? KDNAJSON.canonical(b)) }
    static func normalize(_ request: J, _ view: J) throws -> J {
        var result = request
        if result["selection"] == .null { return result }
        let selection = result["selection"]
        try demand(exact(selection["asset_id"].text, view["asset"]["asset_id"].text), "READ_ASSET_MISMATCH")
        try demand(exact(selection["asset_version"].text, view["asset"]["asset_version"].text), "READ_ASSET_VERSION_MISMATCH")
        let catalog = view["ir"]["catalog"] != .null ? view["ir"]["catalog"] : view["catalog"]
        let wanted = Set(selection["judgment_ids"].list.map { $0.text })
        for id in wanted {
            let count = catalog.list.filter { $0["judgment_id"].text == id }.count
            try demand(count > 0, "READ_SELECTION_NOT_FOUND")
            try demand(count == 1, "READ_SELECTION_AMBIGUOUS")
        }
        result["selection"]["judgment_ids"] = .array(catalog.list.filter { wanted.contains($0["judgment_id"].text) }.map { $0["judgment_id"] })
        return result
    }
    /// selected-context.generated.js: the scoped projection of an IR over
    /// the ordered node ids.
    static func selectedContext(_ ir: J, _ orderedNodeIds: [String]) throws -> J {
        var byId: [String: J] = [:]
        for node in ir["nodes"].list { byId[node["id"].text] = node }
        let original = orderedNodeIds.compactMap { byId[$0] }
        guard original.count == orderedNodeIds.count, Set(orderedNodeIds).count == orderedNodeIds.count else { throw PublicFailure("READ_PROJECTION_INVALID") }
        let supplied = Set(orderedNodeIds)
        func identity(_ target: J) -> String {
            let a = target["asset"]
            let local = a == .null || (exact(a["asset_id"].text, ir["asset"]["asset_id"].text)
                && exact(a["asset_version"].text, ir["asset"]["asset_version"].text)
                && exact(a["judgment_version"].text, ir["asset"]["judgment_version"].text))
            return R2Registry.canonicalKey(.array([target["kind"], target["id"], local ? .null : .array([a["asset_id"], a["asset_version"], a["judgment_version"]])]))
        }
        let targets = Set(original.map { identity($0["target"]) })
        var omissions: [J] = []
        func omit(_ target: String, _ field: String, _ reason: String) {
            omissions.append(["state": "explicitly_omitted", "target": .string(target), "field": .string(field),
                              "reason": .string(reason), "expandable": false, "handle_id": .null])
        }
        var closure: [J] = []
        for node in original {
            var projected = node
            if node["role"].text != "asset_declaration" { closure.append(projected); continue }
            var value = projected["value"]
            if value.has("reading_order") {
                value.remove("reading_order")
                omit(node["id"].text, "reading_order", "not_in_mode")
            }
            let refs = value["kernel"]["foundation_refs"].list
            let filtered = refs.filter { targets.contains(identity($0)) }
            value["kernel"]["foundation_refs"] = .array(filtered)
            if filtered.count != refs.count { omit(node["id"].text, "kernel.foundation_refs", "not_in_mode") }
            projected["value"] = value
            closure.append(projected)
        }
        var judgments = Set(original.filter { $0["role"].text == "judgment" }.map { $0["value"]["id"].text })
        var relationIds = Set<String>()
        for node in original where node["role"].text == "relationship" {
            relationIds.insert(node["value"]["id"].text)
            for participant in node["value"]["participants"].list { judgments.insert(participant["judgment_ref"].text) }
        }
        let catalog = ir["catalog"].list.filter { judgments.contains($0["judgment_id"].text) }
        for item in catalog where !supplied.contains(item["node_ref"].text) { omit(item["node_ref"].text, "judgment", "outside_selection") }
        let references = ir["references"].list.filter { supplied.contains($0["source_node"].text) && supplied.contains($0["target_node"].text) }
        let relationships = ir["relationships"].list.filter { relationIds.contains($0["id"].text) }
        return ["closure": .array(closure), "catalog": .array(catalog), "references": .array(references), "relationships": .array(relationships), "omissions": .array(omissions)]
    }
    static func plan(_ request: J, _ view: J) throws -> J {
        let ir = view["ir"]
        if request["mode"].text == "catalog" {
            let catalog = ir["catalog"] != .null ? ir["catalog"] : view["catalog"]
            let index = ir["asset_index"] != .null ? ir["asset_index"] : view["asset_index"]
            var descriptorIds: [String] = []
            for item in catalog.list + index.list where !descriptorIds.contains(item["node_ref"].text) { descriptorIds.append(item["node_ref"].text) }
            return ["node_ids": .array([]), "descriptor_ids": .array(descriptorIds.map { .string($0) }), "targets": .array([]), "unresolved": false]
        }
        var nodes: [String: J] = [:]
        for node in ir["nodes"].list { nodes[node["id"].text] = node }
        guard let asset = ir["nodes"].list.first(where: { $0["role"].text == "asset_declaration" }) else { throw PublicFailure("READ_PROJECTION_INVALID") }
        let anchor: J = request["selection"] == .null ? ["kind": "asset"] : ["kind": "selection_set", "selection": request["selection"]]
        var seeds = [asset["id"].text]
        if request["selection"] != .null {
            for id in request["selection"]["judgment_ids"].list {
                guard let row = ir["catalog"].list.first(where: { $0["judgment_id"].text == id.text }) else { throw PublicFailure("READ_PROJECTION_INVALID") }
                seeds.append(row["node_ref"].text)
            }
        }
        func closure(_ input: [String]) throws -> [String] {
            var found = Set(input), queue = input
            var cursor = 0
            while cursor < queue.count {
                let current = queue[cursor]; cursor += 1
                for edge in ir["references"].list where edge["mandatory"].boolean && edge["source_node"].text == current && !found.contains(edge["target_node"].text) {
                    guard nodes[edge["target_node"].text] != nil else { throw PublicFailure("READ_PROJECTION_INVALID") }
                    found.insert(edge["target_node"].text)
                    queue.append(edge["target_node"].text)
                }
            }
            return ir["nodes"].list.filter { found.contains($0["id"].text) }.map { $0["id"].text }
        }
        var ids: [String] = []
        var targets: [J] = []
        if request["mode"].text == "whole_asset" {
            ids = ir["asset_closure"].list.map { $0.text }
            targets = ir["expansion_targets"].list.filter { $0["anchor"]["kind"].text == "asset" }
                .map { ["anchor": anchor, "target": $0["target"], "scope": $0["scope"]] }
        } else if request["mode"].text == "exact_selection" {
            var union = Set<String>()
            for id in request["selection"]["judgment_ids"].list {
                guard let row = ir["mandatory_closures"].list.first(where: { $0["selection"]["judgment_id"].text == id.text }) else { throw PublicFailure("READ_PROJECTION_INVALID") }
                for node in row["node_ids"].list { union.insert(node.text) }
            }
            ids = ir["nodes"].list.filter { union.contains($0["id"].text) }.map { $0["id"].text }
            var available = Set(ids)
            for edge in ir["references"].list where union.contains(edge["source_node"].text) && edge["source_node"].text != asset["id"].text {
                available.insert(edge["target_node"].text)
            }
            targets = try ir["nodes"].list.filter { available.contains($0["id"].text) }
                .map { ["anchor": anchor, "target": $0["target"], "scope": .array(try closure(seeds + [$0["id"].text]).map { .string($0) })] }
        } else {
            let handle = request["handle"]
            try demand(same(handle["asset"], view["asset"]), "READ_HANDLE_ASSET_MISMATCH")
            try demand(same(handle["tuple"], view["tuple"]), "READ_HANDLE_VERSION_MISMATCH")
            try demand(same(handle["anchor"], anchor), "READ_HANDLE_ASSET_MISMATCH")
            guard let target = ir["nodes"].list.first(where: { same($0["target"], handle["target"]) }) else { throw PublicFailure("READ_HANDLE_SCOPE_MISMATCH") }
            ids = try closure(seeds + [target["id"].text])
            try demand(same(.array(ids.map { .string($0) }), handle["scope"]), "READ_HANDLE_SCOPE_MISMATCH")
        }
        let scoped = ["exact_selection", "expand"].contains(request["mode"].text) ? try selectedContext(ir, ids) : .null
        var supplied = Set(ids)
        if scoped == .null {
            for node in ir["nodes"].list where node["role"].text == "asset_declaration" { supplied.insert(node["id"].text) }
        }
        var byTarget: [String: J] = [:]
        for item in targets { byTarget[R2Registry.canonicalKey(item["target"])] = item }
        var index: [J] = []
        for descriptor in ir["asset_index"].list {
            guard let node = nodes[descriptor["node_ref"].text] else { throw PublicFailure("READ_PROJECTION_INVALID") }
            let target = byTarget[R2Registry.canonicalKey(descriptor["target"])]
            if request["mode"].text == "expand" && !supplied.contains(node["id"].text) { continue }
            if request["mode"].text != "whole_asset" && node["role"].text == "judgment" && !supplied.contains(node["id"].text) { continue }
            if request["mode"].text != "whole_asset" && !supplied.contains(node["id"].text) && target == nil { continue }
            guard supplied.contains(node["id"].text) || target != nil else { throw PublicFailure("READ_PROJECTION_INVALID") }
            index.append(descriptor)
        }
        let catalog = scoped != .null ? scoped["catalog"] : ir["catalog"]
        let deferred = index.filter { !supplied.contains($0["node_ref"].text) }
        let issued = deferred.map { byTarget[R2Registry.canonicalKey($0["target"])]! }
        let typed = Set(ir["nodes"].list.filter { supplied.contains($0["id"].text) }.map { R2Registry.canonicalKey($0["target"]) })
        var descriptorIds: [String] = []
        for item in catalog.list + index where !descriptorIds.contains(item["node_ref"].text) { descriptorIds.append(item["node_ref"].text) }
        let unresolved = ir["unresolved_external"].list.contains { $0["mandatory"].boolean && typed.contains(R2Registry.canonicalKey($0["source"])) }
        return ["node_ids": .array(ids.map { .string($0) }), "descriptor_ids": .array(descriptorIds.map { .string($0) }),
                "targets": .array(issued), "unresolved": .bool(unresolved), "index": .array(index)]
    }
}
