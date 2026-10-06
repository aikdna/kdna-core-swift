import Foundation
import CryptoKit

// The structural partition observation (section-structure.js +
// section-partition-bindings.js, @aikdna/kdna-core@0.36.0): walk every
// non-xref ordered section with the diagnostic scanner, hash the observed
// reads, check the frame record sets, then re-run the unchanged Core
// registry on the structurally observed registration inputs. Unread body
// text stays unobserved; this is not body schema or domain validation.
enum SectionStructure {
    struct Inspection {
        let observation: J
        let nodes: [J]
        let binding: J
    }
    static func inspectStructure(_ capture: inout SectionFaces.Capture, _ layout: SectionLayout.Layout, _ manifest: J) throws -> Inspection {
        var nodes: [J] = []
        var frames: [J] = []
        for row in layout.ordered {
            if row["kind"].text == "xref" { continue }
            let length = Int(row["length_bytes"].numeric)
            var observed = SHA256()
            let member = row["member"].text, offset = Int(row["offset_bytes"].numeric)
            let scan = try capture.structureAfterAuthorization(member, offset, length) { read in
                try SectionStructureScanner.scanFrame(length) { innerOffset, count, _ in
                    let bytes = try read(innerOffset, count)
                    var header = Data()
                    for shift in stride(from: 56, through: 0, by: -8) { header.append(UInt8(truncatingIfNeeded: UInt64(innerOffset) >> UInt64(shift))) }
                    for shift in stride(from: 56, through: 0, by: -8) { header.append(UInt8(truncatingIfNeeded: UInt64(count) >> UInt64(shift))) }
                    observed.update(data: header)
                    observed.update(data: Data(bytes))
                    return bytes
                }
            }
            // The released C.keys failure is not a SCAN_ failure; the outer
            // boundary maps it to READ_CORE_CAPABILITY_UNAVAILABLE.
            guard scan.partial.has("kind"), scan.partial.has("section_id"), scan.partial.has("records"),
                  scan.partial.fields.count == 3 else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            try demand(scan.partial["kind"].text == row["kind"].text && scan.partial["section_id"].text == row["section_id"].text, "SCAN_FRAME_IDENTITY")
            let expected = Set((layout.tableRows["node_sections"] ?? []).filter { $0["section_id"].text == row["section_id"].text }.map { $0["node_ref"].text })
            let records = scan.partial["records"].list
            try demand(expected.count == records.count && records.allSatisfy { expected.contains($0["id"].text) }, "SCAN_FRAME_RECORDS")
            for node in records {
                let owner = row["kind"].text == "volume" ? "" : String(row["section_id"].text.dropFirst(6))
                let nodeOwner = node["owner_judgment_id"].text
                try demand(row["kind"].text == "volume" ? node["owner_judgment_id"] == .null : nodeOwner == owner, "SCAN_FRAME_OWNER")
                nodes.append(node)
            }
            frames.append(["section_id": row["section_id"], "member": row["member"], "offset_bytes": row["offset_bytes"], "length_bytes": row["length_bytes"],
                           "observed_ranges_digest": .string(sha(Data())), "observed_read_bytes": .number(Double(scan.readBytes)),
                           "read_calls": .number(Double(scan.reads.count)), "skipped_text_bytes": .number(Double(scan.skippedTextBytes)),
                           "frame_digest_status": "not_checked", "unread_text_status": "not_checked"])
            frames[frames.count - 1]["observed_ranges_digest"] = .string("sha256:" + observed.finalize().map { String(format: "%02x", $0) }.joined())
        }
        let binding = try checkPartitionBindings(nodes, manifest, layout.meta)
        let observation: J = ["profile": "kdna.section-structure-observation/0.1.0-candidate", "capture_id": capture.identity["capture_id"], "frames": .array(frames),
                              "registration_partition": "checked_from_observed_registration_fields", "unread_body_semantics": "not_checked"]
        _ = try SectionContract.validate("StructuralPartitionObservation06", observation)
        return Inspection(observation: observation, nodes: nodes, binding: binding)
    }
    static func checkPartitionBindings(_ input: [J], _ manifest: J, _ meta: J) throws -> J {
        let roles: [String: String] = ["asset": "asset_declaration", "contract": "result_contract", "component": "method_component", "unit": "method_unit",
                                       "plan": "method_plan", "plan_node": "method_instance", "policy": "conditional_policy", "branch_entry": "branch"]
        func key(_ target: J) -> String { R2Registry.canonicalKey(.array([target["kind"], target["id"]])) }
        let assets = input.filter { $0["target"]["kind"].text == "asset" }
        try demand(assets.count == 1, "SCAN_ASSET_COUNT")
        let asset = assets[0], assetTarget: J = ["kind": "asset", "id": manifest["asset_uid"]]
        try demand(meta["asset"]["asset_id"].text == manifest["asset_id"].text && meta["asset"]["asset_version"].text == manifest["version"].text
            && meta["asset"]["judgment_version"].text == manifest["judgment_version"].text, "SCAN_ASSET_IDENTITY")
        // JS truthiness of owner/target `asset`: a present non-null object is
        // truthy; the schemas admit no falsy non-null forms.
        func noAsset(_ ref: J) -> Bool { !ref.has("asset") || ref["asset"] == .null }
        try demand(asset["value"]["asset_uid"].text == manifest["asset_uid"].text && key(asset["target"]) == key(assetTarget), "SCAN_VALUE_ASSET_ID")
        var byTarget: [String: J] = [:]
        for node in input {
            let target = node["target"]
            try demand(target.has("kind") && target.has("id") && !target["kind"].text.isEmpty && !target["id"].text.isEmpty, "SCAN_TARGET")
            let k = key(target)
            try demand(byTarget[k] == nil, "SCAN_DUPLICATE_TYPED_ID")
            byTarget[k] = node
        }
        let order = Set(meta["node_order"].list.map { $0.text })
        try demand(input.count == order.count && order.count == meta["node_order"].list.count
            && input.allSatisfy { order.contains($0["id"].text) } && Set(input.map { $0["id"].text }).count == input.count, "SCAN_NODE_SET")
        try demand(meta["asset_index"].list.count == meta["node_order"].list.count
            && meta["asset_index"].list.enumerated().allSatisfy { $0.element["node_ref"].text == meta["node_order"].list[$0.offset].text }, "SCAN_INDEX_ORDER")
        var actualById: [String: J] = [:]
        for node in input { actualById[node["id"].text] = node }
        let nodes = meta["node_order"].list.map { actualById[$0.text]! }
        try demand(nodes.filter { $0["target"]["kind"].text == "judgment" }.map { $0["target"]["id"].text }
            == meta["catalog"].list.map { $0["judgment_id"].text }, "SCAN_CATALOG_ORDER")
        func ownedByAsset(_ node: J) -> Bool {
            noAsset(node["owner"]) && key(node["owner"]) == key(assetTarget) && node["owner_judgment_id"] == .null
        }
        var payload: J = ["asset": meta["asset"], "judgments": .array(nodes.filter { $0["target"]["kind"].text == "judgment" }.map { $0["value"] })]
        for (kind, name) in [("actor", "actors"), ("material", "materials"), ("reason", "reasons"), ("source", "sources"), ("source_use", "source_uses"),
                             ("resource", "resources"), ("relationship", "relationships"), ("dependency", "dependencies"), ("condition", "conditions"),
                             ("shared_declaration", "shared_declarations"), ("example", "examples")] {
            payload[name] = .array(nodes.filter { $0["target"]["kind"].text == kind }.map { $0["value"] })
        }
        for (kind, name) in [("contract", "contracts"), ("exception", "exceptions"), ("misuse", "misuse")] {
            payload[name] = .array(nodes.filter { $0["target"]["kind"].text == kind && ownedByAsset($0) }.map { $0["value"] })
        }
        payload["declarations"] = asset["value"]["declarations"]
        if payload["declarations"]["boundaries"]["state"].text == "provided" {
            payload["declarations"]["boundaries"]["value"] = .array(nodes.filter { $0["target"]["kind"].text == "boundary" && ownedByAsset($0) }.map { $0["value"] })
        }
        let registry = try R2Registry.createRegistry(manifest, payload)
        try demand(registry.ordered.count == nodes.count, "SCAN_REGISTRY_SET")
        try demand(registry.ordered.enumerated().allSatisfy { byTarget[key($0.element.target)]?["id"].text == meta["node_order"].list[$0.offset].text }, "SCAN_REGISTRY_ORDER")
        for expected in registry.ordered {
            guard let node = byTarget[key(expected.target)] else { throw PublicFailure("SCAN_REGISTRY_MISSING") }
            try demand(noAsset(node["owner"]) && key(node["owner"]) == key(expected.owner) && node["owner_judgment_id"] == expected.judgment, "SCAN_REGISTRY_OWNER")
            let role = expected.rawValue["kind"].text == "emission_list" && expected.target["kind"].text == "contract"
                ? "emission_list_contract" : (roles[expected.target["kind"].text] ?? expected.target["kind"].text)
            try demand(node["role"].text == role && node["id"].text == (try SectionLayout.declarationRef(role, [meta["asset"], expected.target])), "SCAN_STABLE_NODE_ID")
            try demand(sha(try KDNAJSON.canonical(node["activation"])) == sha(try KDNAJSON.canonical(expected.activation)), "SCAN_REGISTRY_ACTIVATION")
            if expected.target["kind"].text != "asset" && expected.target["kind"].text != "result" {
                try demand(node["value"]["id"].text == expected.rawValue["id"].text, "SCAN_VALUE_TYPED_ID")
            }
        }
        return ["nodes": .number(Double(nodes.count)), "judgments": .number(Double(payload["judgments"].list.count)),
                "root_records": .number(Double(registry.ordered.filter { $0.judgment == .null }.count)),
                "registry": "Unchanged Core createRegistry on observed registration structure, actual Manifest history and actual asset boundary state. Complete typed target, owner, judgment owner, activation and stable node identity compared.",
                "full_semantic_validation": false]
    }
}
