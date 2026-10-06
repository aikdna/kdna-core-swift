import Foundation

// The mandatory-context fixed point (section-fixedpoint.js,
// @aikdna/kdna-core@0.36.0): load the volume roots and the selected topics,
// then iterate — build the registration payload from the observed nodes,
// run the scoped validator with the missing-body trap armed, derive the
// closure, and load whichever judgment bodies the closure or a trapped read
// actually requires — until the closure is complete; then materialize the
// scoped snapshot body and validate the interpretation inputs.
enum SectionFixedpoint {
    /// registrationPayload: the observed registration nodes re-assembled
    /// into a payload; root kinds are the asset-owned records (owner digest
    /// equals the asset target, no judgment owner).
    static func registrationPayload(_ nodes: [J], _ meta: J, _ manifest: J) throws -> J {
        guard let asset = nodes.first(where: { $0["target"]["kind"].text == "asset" }) else { throw PublicFailure("READ_CORE_INVALID") }
        func same(_ a: J, _ b: J) -> Bool { (try? KDNAJSON.canonical(a)) == (try? KDNAJSON.canonical(b)) }
        func root(_ kind: String) -> [J] {
            nodes.filter { $0["target"]["kind"].text == kind && $0["owner_judgment_id"] == .null && same($0["owner"], asset["target"]) }.map { $0["value"] }
        }
        var payload: J = ["profile": meta["tuple"]["payload_profile"], "profile_version": meta["tuple"]["payload_version"],
                          "asset": meta["asset"],
                          "judgments": .array(nodes.filter { $0["target"]["kind"].text == "judgment" }.map { $0["value"] })]
        for (kind, name) in [("actor", "actors"), ("material", "materials"), ("reason", "reasons"), ("source", "sources"), ("source_use", "source_uses"),
                             ("resource", "resources"), ("relationship", "relationships"), ("dependency", "dependencies"), ("contract", "contracts"),
                             ("condition", "conditions"), ("shared_declaration", "shared_declarations"), ("example", "examples"),
                             ("exception", "exceptions"), ("misuse", "misuse")] {
            payload[name] = .array(root(kind))
        }
        for key in ["scope", "kernel", "reading_order", "cohesion", "attributions", "content_risk", "extensions"] where asset["value"].has(key) {
            payload[key] = asset["value"][key]
        }
        payload["declarations"] = asset["value"]["declarations"]
        if payload["declarations"]["boundaries"] != .null {
            payload["declarations"]["boundaries"]["value"] = payload["declarations"]["boundaries"]["state"].text == "provided" ? .array(root("boundary")) : .null
        }
        return payload
    }
    static func deriveMandatoryContext(_ capture: inout SectionFaces.Capture, _ layout: SectionLayout.Layout, _ manifest: J, _ structure: SectionStructure.Inspection, _ selectedIds: [String], _ optionsTarget: J? = nil, _ optionsScope: [J]? = nil) throws -> J {
        let interpretation = try SectionLoadedValidation.readInterpretationInputs(&capture, layout, structure)
        var loadedRows = Set<String>(), loadedJudgments = Set<String>()
        var loadedJudgmentOrder: [String] = []
        var values: [String: J] = [:]
        for node in structure.nodes { values[node["id"].text] = node }
        var checked: [J] = []
        var iterations: [J] = []
        var entries: [String: [UInt8]] = [:]
        var byJudgment: [String: String] = [:]
        for row in layout.tableRows["topics"] ?? [] { byJudgment[row["judgment_id"].text] = row["section_id"].text }
        func load(_ row: J, _ why: String) throws {
            if loadedRows.contains(row["section_id"].text) { return }
            let frame = try SectionLayout.readFrame(&capture, layout, row, "content")
            _ = try SectionContract.validate("DataFrame06Candidate", frame)
            try demand(frame["kind"].text == row["kind"].text && frame["section_id"].text == row["section_id"].text, "SECTION_FRAME_IDENTITY")
            let expected = Set((layout.tableRows["node_sections"] ?? []).filter { $0["section_id"].text == row["section_id"].text }.map { $0["node_ref"].text })
            let records = frame["records"].list
            try demand(expected.count == records.count && records.allSatisfy { expected.contains($0["id"].text) }, "SECTION_FRAME_RECORD_SET")
            for node in records {
                let owner: J = row["kind"].text == "volume" ? .null : .string(String(row["section_id"].text.dropFirst(6)))
                try demand(node["owner_judgment_id"] == owner, "NODE_OWNER")
                values[node["id"].text] = node
            }
            loadedRows.insert(row["section_id"].text)
            if row["kind"].text == "topic" {
                let id = String(row["section_id"].text.dropFirst(6))
                if loadedJudgments.insert(id).inserted { loadedJudgmentOrder.append(id) }
            }
            checked.append(["section_id": row["section_id"], "member": row["member"], "offset_bytes": row["offset_bytes"],
                            "length_bytes": row["length_bytes"], "digest": row["digest"], "why": .string(why)])
        }
        func loadJudgment(_ id: String, _ why: String) throws {
            guard let section = byJudgment[id], let row = layout.sectionMap[section] else { throw PublicFailure("SECTION_MISSING_JUDGMENT") }
            try load(row, why)
        }
        for row in layout.ordered where row["kind"].text == "volume" { try load(row, "complete incoming root obligations") }
        for id in selectedIds { try loadJudgment(id, "requested selection") }
        for count in 0...layout.ordered.count {
            let nodes = layout.meta["node_order"].list.compactMap { values[$0.text] }
            try demand(nodes.count == layout.meta["node_order"].list.count, "READ_CORE_CAPABILITY_UNAVAILABLE")
            let payload = try registrationPayload(nodes, layout.meta, manifest)
            for resource in payload["resources"].list where entries[resource["entry"].text] == nil {
                entries[resource["entry"].text] = try capture.resourceAfterAuthorization(resource["entry"].text)
            }
            let registry = try R2Registry.createRegistry(manifest, payload)
            var byTarget: [String: J] = [:]
            for node in nodes { byTarget[registry.identity(node["target"])] = node }
            for i in registry.ordered.indices {
                let record = registry.ordered[i]
                if record.judgment != .null && !loadedJudgments.contains(record.judgment.text) {
                    registry.ordered[i].scopeTrap = loadedJudgments
                    continue
                }
                if record.target["kind"].text != "asset" {
                    guard let node = byTarget[registry.identity(record.target)] else { throw PublicFailure("SECTION_LOADED_DUPLICATE_VALUE_MISMATCH") }
                    try demand(sha(try KDNAJSON.canonical(node["value"])) == sha(try KDNAJSON.canonical(record.rawValue)), "SECTION_LOADED_DUPLICATE_VALUE_MISMATCH")
                }
            }
            do {
                try SectionLoadedValidation.validateLoadedSchema(payload, loadedJudgments, interpretation)
                let scope = R2ValidationScope(registry: registry, loadedJudgments: loadedJudgments,
                                              completeJudgments: interpretation["judgments"].list, requireCompletePolicyUses: { _ in })
                let typedEntries = Dictionary(uniqueKeysWithValues: entries.map { (KDNAKey($0.key), Data($0.value)) })
                let r = try R2Semantics.validateR2(manifest, payload, typedEntries, scope)
                var seeds: [J] = [r.asset] + selectedIds.map { R2Registry.ref("judgment", $0) }
                if let optionsTarget { seeds.append(optionsTarget) }
                let closure = try R2Registry.closure(r, seeds)
                var available = Set(closure.map { r.identity($0.target) })
                if optionsTarget == nil {
                    for record in closure where record.target["kind"].text != "asset" {
                        if let edges = r.edges[record.key] { for (key, _) in edges.entries { available.insert(key) } }
                    }
                }
                var targetScopes: [(target: J, records: [R2Registry.Record])] = []
                if optionsTarget == nil {
                    for record in r.ordered where available.contains(r.identity(record.target)) {
                        targetScopes.append((record.target, try R2Registry.closure(r, seeds + [record.target])))
                    }
                }
                let proofRecords = closure + targetScopes.flatMap { $0.records }
                var missing: [String] = []
                for record in proofRecords where record.judgment != .null && !loadedJudgments.contains(record.judgment.text) && !missing.contains(record.judgment.text) {
                    missing.append(record.judgment.text)
                }
                let loadedList: [J] = loadedJudgmentOrder.map { J.string($0) }
                let missingList: [J] = missing.map { J.string($0) }
                let iteration: J = ["iteration": .number(Double(count)), "loaded_judgments": .array(loadedList),
                                    "closure_count": .number(Double(closure.count)), "missing": .array(missingList)]
                if !missing.isEmpty {
                    iterations.append(iteration)
                    for id in missing { try loadJudgment(id, "actual mandatory fixed-point") }
                    continue
                }
                for id in selectedIds {
                    let own = Set(try R2Registry.closure(r, [r.asset, R2Registry.ref("judgment", id)]).map { r.identity($0.target) })
                    let actual = nodes.filter { own.contains(r.identity($0["target"])) }.map { $0["id"].text }
                    guard let declared = layout.meta["mandatory_closures"].list.first(where: { $0["selection"]["judgment_id"].text == id }),
                          sha(try KDNAJSON.canonical(.array(actual.map { J.string($0) }))) == sha(try KDNAJSON.canonical(declared["node_ids"])) else {
                        throw PublicFailure("SECTION_REQUIRED_CONTEXT_MISMATCH")
                    }
                }
                let selected = Set(closure.map { r.identity($0.target) })
                let ordered = nodes.filter { selected.contains(r.identity($0["target"])) }
                var materialized = try SectionScopedMaterialize.materializeScoped(r, payload, manifest, nodes, ordered, selectedIds, layout.meta, loadedJudgments)
                var byKey: [String: J] = [:]
                for node in nodes { byKey[r.identity(node["target"])] = node }
                if let optionsTarget {
                    let orderedIds = Set(ordered.map { $0["id"].text })
                    materialized["asset_index"] = .array(materialized["asset_index"].list.filter { orderedIds.contains($0["node_ref"].text) })
                    _ = optionsTarget
                    try demand(sha(try KDNAJSON.canonical(.array(ordered.map { $0["id"] }))) == sha(try KDNAJSON.canonical(.array(optionsScope ?? []))), "READ_HANDLE_SCOPE_MISMATCH")
                } else {
                    let anchorSelection: J = ["asset_id": payload["asset"]["asset_id"], "asset_version": payload["asset"]["asset_version"],
                                              "judgment_ids": .array(selectedIds.map { J.string($0) })]
                    let anchor: J = ["kind": "selection_set", "selection": anchorSelection]
                    let expansionTargets: [J] = try targetScopes.map { targetScope -> J in
                        let scopeIds: [J] = try targetScope.records.map { record -> J in
                            guard let node = byKey[r.identity(record.target)] else { throw PublicFailure("READ_CORE_INVALID") }
                            return node["id"]
                        }
                        let entry: J = ["anchor": anchor, "target": targetScope.target, "scope": .array(scopeIds)]
                        return entry
                    }
                    materialized["expansion_targets"] = .array(expansionTargets)
                }
                let observation = try SectionLoadedValidation.validateLoadedInterpretation(payload, nodes, loadedJudgments, interpretation, manifest, capture.identity["capture_id"].text)
                var result = materialized
                result["interpretation_observation"] = observation
                result["selected_node_ids"] = .array(ordered.map { $0["id"] })
                result["nodes"] = .array(ordered)
                result["checked_sections"] = .array(checked)
                result["loaded_judgments"] = .array(loadedJudgmentOrder.map { J.string($0) })
                result["iterations"] = .array(iterations + [iteration])
                result["scope"] = "Actual original rules on complete roots and actually loaded selected and expansion-proof topic records. Output nodes contain only requested mandatory closure; all extra proof reads remain in checked_sections and capture I/O."
                return result
            } catch let missingBody as MissingBodyError {
                let bodyIteration: J = ["iteration": .number(Double(count)), "loaded_judgments": .array(loadedJudgmentOrder.map { J.string($0) }), "required_body": .string(missingBody.judgment)]
                iterations.append(bodyIteration)
                try loadJudgment(missingBody.judgment, "original domain rule requires actual value")
            }
        }
        throw PublicFailure("SECTION_FIXEDPOINT_DID_NOT_CONVERGE")
    }
}
