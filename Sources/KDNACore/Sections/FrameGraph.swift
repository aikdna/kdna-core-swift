import Foundation

// frame-local-ordered-scope-dictionary/1: stored xref frames keep a shared
// scope dictionary whose entries are referenced in first-use order.
// Authority: section-scope-codec.js `decodeFrame` (@aikdna/kdna-core@0.36.0).
// The duplicate identity is JSON.stringify(scope) in Node; scope is an array
// of Identifier strings, for which JSON.stringify equals canonical JSON, so
// the canonical-bytes key here is exact.
enum SectionScopeCodec {
    static func decodeFrame(_ stored: J) throws -> J {
        do { try SectionContract.validate("ExperimentalStoredXrefFrame06", stored) }
        catch is PublicFailure { throw PublicFailure("XREF_DICTIONARY_SHAPE") }
        let dictionary = stored["scope_dictionary"].list
        var unique = Set<String>()
        for scope in dictionary {
            let key = String(decoding: try KDNAJSON.canonical(scope), as: UTF8.self)
            try demand(unique.insert(key).inserted, "XREF_DICTIONARY_DUPLICATE")
        }
        var used = Set<Int>(), next = 0
        var records: [J] = []
        for x in stored["records"].list {
            guard isUInt(x["scope_index"]) else { throw PublicFailure("XREF_DICTIONARY_REF") }
            let index = Int(x["scope_index"].numeric)
            try demand(index < dictionary.count, "XREF_DICTIONARY_REF")
            if !used.contains(index) { try demand(index == next, "XREF_DICTIONARY_ORDER"); used.insert(index); next += 1 }
            let restored: J = ["anchor": x["anchor"], "target": x["target"], "scope": dictionary[index]]
            do { _ = try SectionContract.validate("ExpansionTarget", restored) }
            catch is PublicFailure { throw PublicFailure("XREF_RECONSTRUCTED_INVALID") }
            records.append(restored)
        }
        try demand(used.count == dictionary.count, "XREF_DICTIONARY_UNUSED")
        return ["section_id": stored["section_id"], "kind": "xref", "records": .array(records)]
    }
}

// restoreWholeFrames (section-frame-graph.js, @aikdna/kdna-core@0.36.0): the
// pack concatenation walk, the three table directories, the identity graph
// and its closed codes — ported point-by-point. Frames decode through the
// shared strict CBOR walk; object key order is not load-bearing on the Swift
// side (JCS sorts, table/identity checks compare key sets and byte-ordered
// keys).
enum SectionFrameGraph {
    static let tableKeys: [(table: String, key: String)] = [("sections", "section_id"), ("topics", "judgment_id"), ("node_sections", "node_ref")]
    static let rowNames: [String: String] = ["sections": "Representation06DataSectionRow", "topics": "Representation06TopicRow", "node_sections": "Representation06NodeSectionRow"]
    struct Restored {
        let ir: J
        let checkedSections: [J]
        let packNames: [String]
        let sourceIRDigestClaim: String
        let sourceRuntimeEntryNames: J
    }
    static func utf8Less(_ a: String, _ b: String) -> Bool {
        var i = a.utf8.makeIterator(), j = b.utf8.makeIterator()
        while true {
            switch (i.next(), j.next()) {
            case (nil, nil): return false
            case (nil, _): return true
            case (_, nil): return false
            case let (x?, y?): if x != y { return x < y }
            }
        }
    }
    static func utf8Less(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return a.count < b.count
    }
    static func exactKeys(_ value: J, _ keys: [String]) throws {
        guard case .object(let object) = value, object.count == keys.count, keys.allSatisfy({ object[KDNAKey($0)] != nil }) else {
            throw PublicFailure("UNKNOWN_OR_MISSING_FIELD")
        }
    }
    static func sortedUnique(_ values: [J]) throws {
        var previous: [UInt8]?
        for value in values {
            guard case .string(let text) = value else { throw PublicFailure("KEY_ORDER_OR_DUPLICATE") }
            let bytes = Array(text.utf8)
            if let prior = previous { try demand(utf8Less(prior, bytes), "KEY_ORDER_OR_DUPLICATE") }
            previous = bytes
        }
    }
    static func restoreWholeFrames(_ entries: [SectionContainer.Entry], _ publicManifest: J) throws -> Restored {
        try SectionManifest.validate(publicManifest)
        let meta = try MetadataCodec.decode(publicManifest["representation_metadata"])
        var manifest = meta
        manifest["tables"] = publicManifest["payload"]["tables"]
        let members = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0.bytes) })
        let catalogIds = manifest["catalog"].list.map { $0["judgment_id"].text }
        try demand(Set(catalogIds).count == catalogIds.count, "CATALOG_DUPLICATE")
        try demand(manifest["mandatory_closures"].list.count == catalogIds.count, "CLOSURE_COVERAGE")
        for (index, closure) in manifest["mandatory_closures"].list.enumerated() {
            try demand(closure["selection"]["judgment_id"].text == catalogIds[index]
                && closure["selection"]["asset_id"].text == manifest["asset"]["asset_id"].text
                && closure["selection"]["asset_version"].text == manifest["asset"]["asset_version"].text, "CLOSURE_BINDING")
        }
        var tableRows: [String: [J]] = [:], tableFrames: [J] = [], checked: [String] = []
        func frame(_ row: J) throws -> J {
            let member = row["member"].text
            guard let bytes = members[member], isUInt(row["offset_bytes"]), isUInt(row["length_bytes"]) else { throw PublicFailure("FRAME_RANGE") }
            let offset = Int(row["offset_bytes"].numeric), length = Int(row["length_bytes"].numeric)
            try demand(offset <= bytes.count && length <= bytes.count - offset, "FRAME_RANGE")
            let slice = Array(bytes[offset..<offset + length])
            try demand(sha(Data(slice)) == row["digest"].text, "SECTION_DIGEST")
            var decoder = PublicCBOR(bytes: slice)
            let value = try decoder.decode()
            checked.append(row["section_id"].text)
            return value
        }
        var ti = 0
        let tableDirectory = manifest["tables"].list
        for (table, key) in tableKeys {
            var rows: [J] = [], part = 0
            while ti < tableDirectory.count && tableDirectory[ti]["table"].text == table {
                let row = tableDirectory[ti]; ti += 1
                try SectionContract.validate("Representation06TableDirectoryRow", row)
                try demand(row["part"].numeric == Double(part) && row["section_id"].text == "table:\(table):\(part)", "TABLE_PART_SEQUENCE")
                try demand(part == 0 || rows.count == 4096 * part, "TABLE_UNIQUE_CUT")
                try demand(row["rows"].numeric != 0 || part == 0, "EMPTY_PART")
                let items = try frame(row)
                guard case .array(let itemList) = items, itemList.count == Int(row["rows"].numeric) else { throw PublicFailure("TABLE_ROWS") }
                for item in itemList { try SectionContract.validate(rowNames[table]!, item) }
                try demand(row["first_key"] == (itemList.first.map { $0[key] } ?? .null) && row["last_key"] == (itemList.last.map { $0[key] } ?? .null), "TABLE_KEYS")
                rows.append(contentsOf: itemList); tableFrames.append(row); part += 1
            }
            try demand(part > 0, "MISSING_TABLE")
            try sortedUnique(rows.map { $0[key] })
            tableRows[table] = rows
        }
        try demand(ti == tableDirectory.count, "TABLE_DIRECTORY_ORDER")
        let sections = tableRows["sections"]!
        var sectionMap: [String: J] = [:]
        for section in sections { sectionMap[section["section_id"].text] = section }
        var nodeMap: [String: String] = [:]
        for row in tableRows["node_sections"]! { nodeMap[row["node_ref"].text] = row["section_id"].text }
        try demand(nodeMap.count == manifest["node_order"].list.count && manifest["node_order"].list.allSatisfy { nodeMap[$0.text] != nil }, "NODE_MAP_COVERAGE")
        for (_, sectionId) in nodeMap {
            guard let section = sectionMap[sectionId] else { throw PublicFailure("NODE_MAP_TARGET") }
            try demand(section["kind"].text != "xref", "NODE_MAP_TARGET")
        }
        try demand(tableRows["topics"]!.count == catalogIds.count, "TOPIC_COVERAGE")
        for item in manifest["catalog"].list {
            let judgmentId = item["judgment_id"].text
            guard let row = tableRows["topics"]!.first(where: { $0["judgment_id"].text == judgmentId }),
                  let section = sectionMap[row["section_id"].text] else { throw PublicFailure("TOPIC_MAP") }
            try demand(row["section_id"].text == "topic:" + judgmentId && section["kind"].text == "topic" && nodeMap[item["node_ref"].text] == row["section_id"].text, "TOPIC_MAP")
        }
        for closure in manifest["mandatory_closures"].list {
            try demand(closure["node_ids"].list.allSatisfy { nodeMap[$0.text] != nil }, "CLOSURE_NODE_MISSING")
        }
        var ordered: [J] = []
        func anchor(_ ordinal: Int) throws {
            let chunk = sections.filter { $0["section_id"].text.hasPrefix("xref:\(ordinal):") }.sorted { $0["pack_ordinal"].numeric < $1["pack_ordinal"].numeric }
            for (index, row) in chunk.enumerated() {
                try demand(row["kind"].text == "xref" && row["section_id"].text == "xref:\(ordinal):\(index)" && (index == chunk.count - 1 || row["entry_count"].numeric == 1024), "XREF_CHUNK")
            }
            ordered.append(contentsOf: chunk)
        }
        try anchor(0)
        for (index, judgmentId) in catalogIds.enumerated() {
            ordered.append(sectionMap["topic:" + judgmentId]!)
            try anchor(index + 1)
        }
        let volumes = sections.filter { $0["kind"].text == "volume" }.sorted { $0["pack_ordinal"].numeric < $1["pack_ordinal"].numeric }
        for (index, volume) in volumes.enumerated() { try demand(volume["section_id"].text == "volume:\(index)", "VOLUME_SEQUENCE") }
        ordered.append(contentsOf: volumes)
        let volumeIds = tableRows["node_sections"]!.filter { row in
            guard let section = sectionMap[row["section_id"].text] else { return false }
            return section["kind"].text == "volume"
        }.map { $0["node_ref"].text }.sorted(by: utf8Less)
        try demand(volumes.count == (volumeIds.count + 511) / 512, "VOLUME_FIXED_CHUNKS")
        for (index, id) in volumeIds.enumerated() { try demand(nodeMap[id] == "volume:\(index / 512)", "VOLUME_FIXED_CHUNKS") }
        try demand(ordered.count == sections.count && Set(ordered.map { $0["section_id"].text }).count == sections.count, "SECTION_COVERAGE")
        let all = ordered + tableFrames
        var packNames: [String] = [], packEnds: [String: Int] = [:]
        for (index, row) in all.enumerated() {
            let member = "sections/pack-\(index / 8).kdnab"
            try demand(row["pack_ordinal"].numeric == Double(index) && row["member"].text == member && row["offset_bytes"].numeric == Double(packEnds[member] ?? 0), "FRAME_PACK_ORDER_OR_OVERLAP")
            if packEnds[member] == nil { packNames.append(member) }
            packEnds[member] = Int(row["offset_bytes"].numeric) + Int(row["length_bytes"].numeric)
        }
        try demand(packEnds.count == members.keys.filter { $0.hasPrefix("sections/") }.count, "PACK_COVERAGE")
        for (name, length) in packEnds { try demand(members[name]?.count == length, "PACK_SPAN_COVERAGE") }
        var nodes: [String: J] = [:]
        var expansions: [J] = []
        for row in ordered {
            let stored = try frame(row)
            let value = row["kind"].text == "xref" ? try SectionScopeCodec.decodeFrame(stored) : stored
            try exactKeys(value, ["section_id", "kind", "records"])
            try demand(value["section_id"] == row["section_id"] && value["kind"] == row["kind"] && { if case .array = value["records"] { return true }; return false }(), "FRAME_SHAPE")
            if row["kind"].text == "xref" {
                let records = value["records"].list
                try demand(records.count == Int(row["entry_count"].numeric) && records.count <= 1024, "XREF_ENTRY_COUNT")
                let ordinal = Int(row["section_id"].text.split(separator: ":")[1])!
                for x in records {
                    try SectionContract.validate("ExpansionTarget", x)
                    try demand(x["scope"].list.allSatisfy { nodeMap[$0.text] != nil }, "XREF_SCOPE")
                    if ordinal == 0 {
                        try demand(x["anchor"]["kind"].text == "asset", "XREF_ANCHOR")
                    } else {
                        try demand(x["anchor"]["kind"].text == "judgment"
                            && x["anchor"]["selection"]["judgment_id"].text == catalogIds[ordinal - 1]
                            && x["anchor"]["selection"]["asset_id"].text == manifest["asset"]["asset_id"].text
                            && x["anchor"]["selection"]["asset_version"].text == manifest["asset"]["asset_version"].text, "XREF_ANCHOR")
                    }
                }
                expansions.append(contentsOf: records)
            } else {
                let expected = tableRows["node_sections"]!.filter { $0["section_id"] == row["section_id"] }.map { $0["node_ref"].text }.sorted(by: utf8Less)
                let actual = value["records"].list.map { $0["id"].text }.sorted(by: utf8Less)
                try demand(expected == actual, "FRAME_NODE_COVERAGE")
                if row["kind"].text == "volume" {
                    try demand(value["records"].list.count <= 512, "VOLUME_CHUNK")
                    try sortedUnique(value["records"].list.map { $0["id"] })
                }
                for record in value["records"].list {
                    try SectionContract.validate("IRReadNode", record)
                    try demand(nodes[record["id"].text] == nil, "DUPLICATE_RECORD")
                    if row["kind"].text == "volume" {
                        try demand(record["owner_judgment_id"] == .null, "NODE_OWNER")
                    } else {
                        try demand("topic:" + record["owner_judgment_id"].text == row["section_id"].text, "NODE_OWNER")
                    }
                    nodes[record["id"].text] = record
                }
            }
        }
        var outputNodes: [J] = []
        for id in manifest["node_order"].list {
            guard let node = nodes[id.text] else { throw PublicFailure("REQUIRED_NODE_MISSING") }
            outputNodes.append(node)
        }
        var components = meta
        components.remove("node_order"); components.remove("ir_digest_claim"); components.remove("runtime_entry_names")
        var ir = components
        ir["nodes"] = .array(outputNodes)
        ir["expansion_targets"] = .array(expansions)
        let checkedSections = (ordered + tableFrames).map { row -> J in
            ["section_id": row["section_id"], "member": row["member"], "offset_bytes": row["offset_bytes"], "length_bytes": row["length_bytes"], "digest": row["digest"]]
        }
        return Restored(ir: ir, checkedSections: checkedSections, packNames: packNames, sourceIRDigestClaim: meta["ir_digest_claim"].text, sourceRuntimeEntryNames: meta["runtime_entry_names"])
    }
}
