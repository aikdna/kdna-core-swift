import Foundation

// The section layout walk (section-layout.js, @aikdna/kdna-core@0.36.0):
// the metadata bindings, the table directory/frame walk with every closed
// code, the section/topic/volume coverage obligations, the mandated physical
// order reconstruction and the pack span checks. This is the layout the
// catalog face reports and the partial (scoped) faces build on.
enum SectionLayout {
    struct Layout {
        let meta: J
        let manifest: J
        let tableRows: [String: [J]]
        let sectionMap: [String: J]
        let nodeMap: [String: String]
        let ordered: [J]
        let tableFrames: [J]
        let packNames: [String]
        let checkedSections: [J]
    }
    static func declarationRef(_ role: String, _ parts: [J]) throws -> String {
        let digest = sha(try KDNAJSON.canonical(.array(parts)))
        return role + ":" + String(digest.dropFirst(7).prefix(40))
    }
    /// The metadata bindings admitPartialSectionNode and readSectionLayout both
    /// enforce (the released code keeps two identical inline copies).
    static func checkMetadataBindings(_ manifest: J, _ meta: J, _ tuple: J) throws {
        try demand(exact(meta["asset"]["asset_id"].text, manifest["asset_id"].text)
            && exact(meta["asset"]["asset_version"].text, manifest["version"].text)
            && exact(meta["asset"]["judgment_version"].text, manifest["judgment_version"].text), "SECTION_METADATA_IDENTITY")
        try demand(sha(try KDNAJSON.canonical(meta["tuple"])) == sha(try KDNAJSON.canonical(tuple)), "SECTION_METADATA_TUPLE")
        var indexByNode: [String: J] = [:]
        for descriptor in meta["asset_index"].list { indexByNode[descriptor["node_ref"].text] = descriptor }
        let order = meta["node_order"].list.map { $0.text }
        try demand(indexByNode.count == meta["asset_index"].list.count && indexByNode.count == order.count
            && order.allSatisfy { indexByNode[$0] != nil }, "SECTION_METADATA_INDEX_COVERAGE")
        let assets = meta["asset_index"].list.filter { $0["target"]["kind"].text == "asset" }
        if assets.count == 1 {
            let descriptor = assets[0]
            let nodeRef = try declarationRef("asset_declaration", [meta["asset"], descriptor["target"]])
            try demand(exact(descriptor["target"]["id"].text, manifest["asset_uid"].text)
                && descriptor["target"]["asset"] == .null
                && sha(try KDNAJSON.canonical(descriptor["owner"])) == sha(try KDNAJSON.canonical(descriptor["target"]))
                && exact(descriptor["display_name"].text, manifest["title"].text)
                && exact(descriptor["node_ref"].text, nodeRef), "SECTION_METADATA_ASSET_BINDING")
        } else {
            throw PublicFailure("SECTION_METADATA_ASSET_BINDING")
        }
        let catalogIds = Set(meta["catalog"].list.map { $0["judgment_id"].text })
        try demand(catalogIds.count == meta["catalog"].list.count, "CATALOG_DUPLICATE")
        for item in meta["catalog"].list {
            guard let descriptor = indexByNode[item["node_ref"].text] else { throw PublicFailure("SECTION_METADATA_CATALOG_BINDING") }
            let nodeRef = try declarationRef("judgment", [meta["asset"], descriptor["target"]])
            try demand(descriptor["target"]["kind"].text == "judgment"
                && exact(descriptor["target"]["id"].text, item["judgment_id"].text)
                && descriptor["target"]["asset"] == .null
                && exact(item["node_ref"].text, nodeRef)
                && exact(descriptor["display_name"].text, item["focus"].text)
                && (item["parent_ref"] == .null || catalogIds.contains(item["parent_ref"].text)), "SECTION_METADATA_CATALOG_BINDING")
        }
    }
    static func readSectionLayout(_ capture: inout SectionFaces.Capture, _ publicManifest: J) throws -> Layout {
        _ = try SectionContract.validate("Manifest06Candidate", publicManifest)
        let meta = try MetadataCodec.decode(publicManifest["representation_metadata"])
        var manifest = meta
        manifest["tables"] = publicManifest["payload"]["tables"]

        var members: [String: Int] = [:]
        for row in capture.rows { members[row.name] = row.size }
        let catalogIds = meta["catalog"].list.map { $0["judgment_id"].text }
        try demand(Set(catalogIds).count == catalogIds.count, "CATALOG_DUPLICATE")
        try demand(meta["mandatory_closures"].list.count == catalogIds.count, "CLOSURE_COVERAGE")
        for (i, closure) in meta["mandatory_closures"].list.enumerated() {
            try demand(exact(closure["selection"]["judgment_id"].text, catalogIds[i])
                && exact(closure["selection"]["asset_id"].text, meta["asset"]["asset_id"].text)
                && exact(closure["selection"]["asset_version"].text, meta["asset"]["asset_version"].text), "CLOSURE_BINDING")
        }
        var tableRows: [String: [J]] = [:]
        var tableFrames: [J] = []
        var checked: [String] = []
        func frame(_ row: J, _ category: String) throws -> J {
            guard let memberSize = members[row["member"].text] else { throw PublicFailure("FRAME_RANGE") }
            let offset = row["offset_bytes"].numeric, length = row["length_bytes"].numeric
            try demand(isUInt(row["offset_bytes"]) && isUInt(row["length_bytes"]) && offset + length <= Double(memberSize), "FRAME_RANGE")
            let bytes = try capture.sectionAfterAuthorization(row["member"].text, Int(offset), Int(length))
            try demand(sha(Data(bytes)) == row["digest"].text, "SECTION_DIGEST")
            checked.append(row["section_id"].text)
            return try frameValue(bytes)
        }
        var ti = 0
        for (table, key) in SectionFrameGraph.tableKeys {
            var rows: [J] = []
            var part = 0
            while ti < manifest["tables"].list.count && manifest["tables"].list[ti]["table"].text == table {
                let row = manifest["tables"].list[ti]; ti += 1
                _ = try SectionContract.validate("Representation06TableDirectoryRow", row)
                try demand(Int(row["part"].numeric) == part && exact(row["section_id"].text, "table:\(table):\(part)"), "TABLE_PART_SEQUENCE")
                try demand(part == 0 || rows.count == 4096 * part, "TABLE_UNIQUE_CUT")
                try demand(row["rows"].numeric != 0 || part == 0, "EMPTY_PART")
                let decoded = try frame(row, "metadata")
                guard case .array(let items) = decoded else { throw PublicFailure("TABLE_ROWS") }
                try demand(Double(items.count) == row["rows"].numeric, "TABLE_ROWS")
                for item in items { _ = try SectionContract.validate(SectionFrameGraph.rowNames[table]!, item) }
                try demand(row["first_key"] == (items.first?[key] ?? .null) && row["last_key"] == (items.last?[key] ?? .null), "TABLE_KEYS")
                rows.append(contentsOf: items)
                tableFrames.append(row)
                part += 1
            }
            try demand(part > 0, "MISSING_TABLE")
            try SectionFrameGraph.sortedUnique(rows.map { $0[key] })
            tableRows[table] = rows
        }
        try demand(ti == manifest["tables"].list.count, "TABLE_DIRECTORY_ORDER")
        let sections = tableRows["sections"] ?? []
        var sectionMap: [String: J] = [:]
        for section in sections { sectionMap[section["section_id"].text] = section }
        var nodeMap: [String: String] = [:]
        for row in tableRows["node_sections"] ?? [] { nodeMap[row["node_ref"].text] = row["section_id"].text }
        let nodeOrder = meta["node_order"].list.map { $0.text }
        try demand(nodeMap.count == nodeOrder.count && nodeOrder.allSatisfy { nodeMap[$0] != nil }, "NODE_MAP_COVERAGE")
        for (_, sid) in nodeMap {
            guard let section = sectionMap[sid] else { throw PublicFailure("NODE_MAP_TARGET") }
            try demand(section["kind"].text != "xref", "NODE_MAP_TARGET")
        }
        try demand((tableRows["topics"] ?? []).count == catalogIds.count, "TOPIC_COVERAGE")
        for c in meta["catalog"].list {
            guard let row = (tableRows["topics"] ?? []).first(where: { exact($0["judgment_id"].text, c["judgment_id"].text) }) else { throw PublicFailure("TOPIC_MAP") }
            try demand(exact(row["section_id"].text, "topic:" + c["judgment_id"].text)
                && sectionMap[row["section_id"].text]?["kind"].text == "topic"
                && exact(nodeMap[c["node_ref"].text] ?? "", row["section_id"].text), "TOPIC_MAP")
        }
        for closure in meta["mandatory_closures"].list {
            for id in closure["node_ids"].list where nodeMap[id.text] == nil { throw PublicFailure("CLOSURE_NODE_MISSING") }
        }
        // Reconstruct the mandated physical order from identities, not table sorting order.
        var ordered: [J] = []
        func anchor(_ ordinal: Int) throws {
            let xs = sections.filter { $0["section_id"].text.hasPrefix("xref:\(ordinal):") }
                .sorted { $0["pack_ordinal"].numeric < $1["pack_ordinal"].numeric }
            for (i, r) in xs.enumerated() {
                try demand(r["kind"].text == "xref" && exact(r["section_id"].text, "xref:\(ordinal):\(i)")
                    && (i == xs.count - 1 || r["entry_count"].numeric == 1024), "XREF_CHUNK")
            }
            ordered.append(contentsOf: xs)
        }
        try anchor(0)
        for (i, jid) in catalogIds.enumerated() {
            ordered.append(sectionMap["topic:" + jid]!)
            try anchor(i + 1)
        }
        let volumes = sections.filter { $0["kind"].text == "volume" }.sorted { $0["pack_ordinal"].numeric < $1["pack_ordinal"].numeric }
        for (i, v) in volumes.enumerated() { try demand(exact(v["section_id"].text, "volume:\(i)"), "VOLUME_SEQUENCE") }
        ordered.append(contentsOf: volumes)
        let volumeIds = (tableRows["node_sections"] ?? []).filter { sectionMap[$0["section_id"].text]?["kind"].text == "volume" }
            .map { $0["node_ref"].text }.sorted(by: SectionFrameGraph.utf8Less)
        try demand(volumes.count == (volumeIds.count + 511) / 512, "VOLUME_FIXED_CHUNKS")
        for (i, id) in volumeIds.enumerated() {
            try demand(exact(nodeMap[id] ?? "", "volume:\(i / 512)"), "VOLUME_FIXED_CHUNKS")
        }
        try demand(ordered.count == sections.count && Set(ordered.map { $0["section_id"].text }).count == sections.count, "SECTION_COVERAGE")
        var packEnds: [String: Int] = [:]
        let all = ordered + tableFrames
        for (i, r) in all.enumerated() {
            let member = "sections/pack-\(i / 8).kdnab"
            try demand(Int(r["pack_ordinal"].numeric) == i && exact(r["member"].text, member)
                && Int(r["offset_bytes"].numeric) == (packEnds[member] ?? 0), "FRAME_PACK_ORDER_OR_OVERLAP")
            packEnds[member] = Int(r["offset_bytes"].numeric) + Int(r["length_bytes"].numeric)
        }
        try demand(packEnds.count == members.keys.filter { $0.hasPrefix("sections/") }.count, "PACK_COVERAGE")
        for (name, length) in packEnds {
            try demand(members[name] == length, "PACK_SPAN_COVERAGE")
        }
        let checkedSections = tableFrames.map { row -> J in
            var out: J = [:]
            for key in ["section_id", "member", "offset_bytes", "length_bytes", "digest"] { out[key] = row[key] }
            return out
        }
        return Layout(meta: meta, manifest: manifest, tableRows: tableRows, sectionMap: sectionMap,
                      nodeMap: nodeMap, ordered: ordered, tableFrames: tableFrames,
                      packNames: Array(packEnds.keys), checkedSections: checkedSections)
    }
    /// C.decode: the frame bytes decode as CBOR.
    static func frameValue(_ bytes: [UInt8]) throws -> J {
        var decoder = PublicCBOR(bytes: bytes)
        return try decoder.decode()
    }
    /// The Node layout readFrame: member bounds, the section read (touching
    /// the member), the digest check and the frame decode.
    static func readFrame(_ capture: inout SectionFaces.Capture, _ layout: Layout, _ row: J, _ category: String) throws -> J {
        var members: [String: Int] = [:]
        for r in capture.rows { members[r.name] = r.size }
        guard let memberSize = members[row["member"].text] else { throw PublicFailure("FRAME_RANGE") }
        let offset = row["offset_bytes"].numeric, length = row["length_bytes"].numeric
        try demand(isUInt(row["offset_bytes"]) && isUInt(row["length_bytes"]) && offset + length <= Double(memberSize), "FRAME_RANGE")
        let bytes = try capture.sectionAfterAuthorization(row["member"].text, Int(offset), Int(length))
        try demand(sha(Data(bytes)) == row["digest"].text, "SECTION_DIGEST")
        return try frameValue(bytes)
    }
}
