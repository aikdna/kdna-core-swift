import Foundation

enum PublicDigests {
    static func word(_ n: Int, _ width: Int) throws -> Data {
        try demand(n >= 0 && n <= 9007199254740991 && (width != 4 || n <= 0xffffffff), "READ_INPUT_INVALID")
        return Data((0..<width).reversed().map { UInt8(truncatingIfNeeded: n >> ($0 * 8)) })
    }
    static func sorted(_ names: [KDNAKey]) -> [KDNAKey] { names.sorted { $0.text.utf8.lexicographicallyPrecedes($1.text.utf8) } }
    static func content(_ entries: [KDNAKey:Data]) throws -> Data {
        let names = sorted(entries.keys.filter { $0 != "checksums.json" && $0 != "signature.kdsig" })
        var out = Data("KDNA-CONTENT-TREE\0".utf8) + Data("0.2.0\0".utf8)
        out += try word(names.count, 4)
        for key in names {
            var bytes = entries[key]!
            let json = key.text.hasSuffix(".json")
            if json {
                var value = try KDNAJSON.parse(bytes)
                if key == "kdna.json" {
                    value.remove("content_digest")
                    if value.has("authoring") {
                        try demand(PublicSchema.typeMatches(value["authoring"], "object"), "READ_INPUT_INVALID")
                        var authoring = value["authoring"]; authoring.remove("content_digest"); value["authoring"] = authoring
                    }
                }
                bytes = try KDNAJSON.canonical(value)
            }
            let name = Data(key.text.utf8)
            out += try word(name.count, 4); out += name; out.append(json ? 0 : 1)
            out += try word(bytes.count, 8); out += bytes
        }
        return out
    }
    static func runtimeNames(_ entries: [KDNAKey:Data], _ manifest: J) throws -> [KDNAKey] {
        let declared = manifest["runtime"]["mandatory_entries"].list.map { KDNAKey($0.text) }
        try demand(Set(declared).count == declared.count && declared.allSatisfy { validEntry($0.text) && ![KDNAKey("checksums.json"), "signature.kdsig", "mimetype"].contains($0) })
        let names = sorted(Array(Set([KDNAKey("kdna.json"), "payload.kdnab"] + declared)))
        try demand(names.allSatisfy { entries[$0] != nil }); return names
    }
    static func runtime(_ entries: [KDNAKey:Data], _ manifest: J) throws -> Data {
        let names = try runtimeNames(entries, manifest)
        var out = Data("KDNA-RUNTIME-ENTRY-SET\0".utf8) + Data("0.2.0\0".utf8)
        out += try word(names.count, 4)
        for key in names {
            let name = Data(key.text.utf8), bytes = entries[key]!
            out += try word(name.count, 4); out += name; out += try word(bytes.count, 8); out += bytes
        }
        return out
    }
    static func evidence(_ key: String, _ observed: String, expected: J = nil) -> J {
        let pairs = ["A": ("container_bytes", "container-bytes"), "C": ("content_tree", "content-tree"), "E": ("runtime_entry_set", "runtime-entry-set")]
        let pair = pairs[key]!
        let comparison: J = expected == .null ? ["state": "not_compared", "expected": nil, "expected_source": nil] : ["state": .string(exact(expected.text, observed) ? "matched" : "mismatched"), "expected": expected, "expected_source": ["kind": "manifest_declaration", "source_id": "kdna.json"]]
        return ["basis": .string(pair.0), "profile": .string("kdna.digest-basis." + pair.1), "profile_version": "0.2.0", "algorithm": "SHA-256", "observed": .string(observed), "comparison": comparison]
    }
}
