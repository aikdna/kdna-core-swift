import Foundation

// The sections digest set and payload reconstruction (section-digests.js,
// digests.js and section-reconstruct.js, @aikdna/kdna-core@0.36.0):
//
//   A = the whole container bytes
//   C = the shared content-tree preimage (checksums.json and signature.kdsig
//       excluded; kdna.json's content_digest and authoring.content_digest
//       deleted before canonicalization) — reuses the shared
//       PublicDigests.content port
//   E = observeE on the kdna.digest-basis.runtime-entry-set/0.3.0-candidate
//       profile (kdna.json, the packs, and the declared mandatory entries)
//
// reconstructPayload rebuilds the 0.5.1 payload from the whole-frame IR the
// way the producer does; its SECTION_* codes are verbatim.
enum SectionDigests {
    static func word(_ n: Int, _ width: Int) throws -> Data {
        try demand(n >= 0 && n <= 9007199254740991 && (width != 4 || n <= 0xffffffff), "SECTION_DIGEST_LENGTH")
        return Data((0..<width).reversed().map { UInt8(truncatingIfNeeded: n >> ($0 * 8)) })
    }
    static func observeE(_ entries: [SectionContainer.Entry], _ manifest: J, _ packNames: [String]) throws -> J {
        let actualPacks = entries.map { $0.name }.filter { $0.hasPrefix("sections/") }.sorted(by: SectionFrameGraph.utf8Less)
        try demand(actualPacks == packNames.sorted(by: SectionFrameGraph.utf8Less), "SECTION_E_PACK_COVERAGE")
        guard case .array(let declaredValues) = manifest["runtime"]["mandatory_entries"] else { throw PublicFailure("SECTION_RUNTIME_DECLARATION") }
        let declared = declaredValues.map { $0.text }
        try demand(Set(declared).count == declared.count, "SECTION_RUNTIME_DECLARATION")
        let memberBytes = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0.bytes) })
        for name in declared {
            try demand(validEntry(name) && memberBytes[name] != nil
                && !["checksums.json", "signature.kdsig", "mimetype", "build-receipt.json"].contains(name)
                && !name.hasPrefix("reports/") && !name.hasPrefix("authoring/"), "SECTION_RUNTIME_MEMBER_MISSING")
        }
        var nameSet = Set(["kdna.json"]); actualPacks.forEach { nameSet.insert($0) }; declared.forEach { nameSet.insert($0) }
        let names = nameSet.sorted(by: SectionFrameGraph.utf8Less)
        var out = Data("KDNA-RUNTIME-ENTRY-SET\0".utf8) + Data("0.3.0-candidate\0".utf8)
        out += try word(names.count, 4)
        for name in names {
            guard let bytes = memberBytes[name] else { throw PublicFailure("SECTION_RUNTIME_MEMBER_MISSING") }
            let nameBytes = Data(name.utf8)
            out += try word(nameBytes.count, 4); out += nameBytes; out += try word(bytes.count, 8); out += bytes
        }
        return ["status": "verified", "profile": "kdna.digest-basis.runtime-entry-set/0.3.0-candidate",
                "digest": .string(sha(out)), "member_names": .array(names.map { .string($0) })]
    }
    static func observeWhole(_ bytes: [UInt8], _ entries: [SectionContainer.Entry], _ manifest: J, _ packNames: [String]) throws -> (A: String, C: String, E: J) {
        let map = Dictionary(uniqueKeysWithValues: entries.map { (KDNAKey($0.name), Data($0.bytes)) })
        return (sha(Data(bytes)), sha(try PublicDigests.content(map)), try observeE(entries, manifest, packNames))
    }
    static func assertContentBindings(_ manifest: J, _ C: String) throws {
        for declared in [manifest["content_digest"], manifest["authoring"]["content_digest"]] where declared != .null {
            try demand(declared.text == C, "READ_CORE_INVALID")
        }
    }
    static func reconstructPayload(_ ir: J) throws -> J {
        try SectionContract.validate("CanonicalIR06Candidate", ir)
        let nodes = ir["nodes"].list
        let assets = nodes.filter { $0["target"]["kind"].text == "asset" }
        try demand(assets.count == 1, "SECTION_ASSET_NODE")
        let value = assets[0]["value"], assetTarget = assets[0]["target"]
        func same(_ a: J, _ b: J) -> Bool {
            guard let left = try? KDNAJSON.canonical(a), let right = try? KDNAJSON.canonical(b) else { return false }
            return left == right
        }
        func collection(_ kind: String) -> [J] {
            nodes.filter { $0["target"]["kind"].text == kind && $0["owner_judgment_id"] == .null && same($0["owner"], assetTarget) }.map { $0["value"] }
        }
        var payload: J = ["profile": ir["tuple"]["payload_profile"], "profile_version": ir["tuple"]["payload_version"], "asset": ir["asset"]]
        for (kind, key) in [("actor", "actors"), ("material", "materials"), ("reason", "reasons"), ("source", "sources"), ("source_use", "source_uses"), ("resource", "resources"), ("relationship", "relationships"), ("dependency", "dependencies"), ("contract", "contracts"), ("condition", "conditions"), ("shared_declaration", "shared_declarations"), ("example", "examples"), ("exception", "exceptions"), ("misuse", "misuse")] {
            payload[key] = .array(collection(kind))
        }
        let judgments = nodes.filter { $0["target"]["kind"].text == "judgment" }.map { $0["value"] }
        payload["judgments"] = .array(judgments)
        var forms = Set<String>()
        for judgment in judgments { forms.insert(judgment["form"].text) }
        try demand(!forms.isEmpty && forms.allSatisfy { $0 == "rule" || $0 == "conclusion" }, "SECTION_FORM_INVALID")
        payload["asset_capability"] = .string(forms.count == 2 ? "mixed" : forms.contains("rule") ? "result_forming_rules" : "asserted_answers")
        for key in ["scope", "kernel", "reading_order", "cohesion", "attributions", "content_risk", "extensions"] where value.has(key) { payload[key] = value[key] }
        var declarations = value["declarations"]
        if declarations.has("boundaries") {
            var boundaries = declarations["boundaries"]
            boundaries["value"] = boundaries["state"].text == "provided" ? .array(collection("boundary")) : .null
            declarations["boundaries"] = boundaries
        }
        payload["declarations"] = declarations
        return payload
    }
}
