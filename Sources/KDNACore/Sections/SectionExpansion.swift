import Foundation

// The expansion origin registry and binding (section-expansion.js,
// @aikdna/kdna-core@0.36.0): an accepted read retains its origin record
// (the released WeakMap keyed by the opaque snapshot token; the port keeps
// the record on the snapshot object — same lifetime semantics, no global
// map). A bind validates a caller-provided ExpansionHandle against the
// retained view — snapshot identity, digests, tuple, anchor, target and
// scope — and yields the binding the expand read consumes. The capture
// re-check compares the source identity and the manifest/directory digests
// (the in-memory variant's source identity is empty; recorded).
enum SectionExpansion {
    struct Binding {
        let request: J
        let origin: J
        let target: J
        let scope: [J]
        let anchor: J
        let sourceIdentity: String
    }
    static func originValue(_ view: J) -> J {
        let capture = view["verification"]["capture"]
        return ["snapshot_id": view["snapshot_id"],
                "request_digest": view["request_digest"] != .null ? view["request_digest"] : view["verification"]["request_digest"],
                "capture_id": capture["capture_id"],
                "input_byte_length": capture["input_byte_length"],
                "manifest_bytes_digest": capture["manifest_bytes_digest"],
                "zip_directory_bytes_digest": capture["zip_directory_bytes_digest"],
                "checked_sections_digest": .string(sha(try! KDNAJSON.canonical(view["verification"]["checked_sections"])))]
    }
    static func retain(_ snapshot: KDNASectionSnapshot, _ view: J, _ capture: SectionFaces.Capture) {
        snapshot.retainedOrigin = ["view": view, "origin": originValue(view)]
        snapshot.retainedSourceIdentity = capture.sourceIdentity()
    }
    static func same(_ a: J, _ b: J) -> Bool { (try? KDNAJSON.canonical(a)) == (try? KDNAJSON.canonical(b)) }
    static func bind(_ snapshot: KDNASectionSnapshot, _ request: J) throws -> Binding {
        guard let retained = snapshot.retainedOrigin, request["mode"].text == "expand" else { throw PublicFailure("READ_HANDLE_UNTRUSTED") }
        let view = retained["view"], recordOrigin = retained["origin"]
        let handle = request["handle"]
        let whole = view["verification"]["mode"].text == "whole_asset"
        try demand(same(request["tuple"], view["tuple"]), "READ_HANDLE_VERSION_MISMATCH")
        var selection: J?
        let anchor: J
        if whole {
            try demand(handle["binding_kind"] == .null && same(handle["snapshot_id"], view["snapshot_id"])
                && same(handle["A"], view["digests"]["A"]["observed"]) && same(handle["C"], view["digests"]["C"]["observed"]), "READ_HANDLE_STALE")
            try demand(same(handle["asset_id"], view["asset"]["asset_id"]) && same(handle["asset_version"], view["asset"]["asset_version"])
                && same(handle["core_version"], view["tuple"]["core"]) && same(handle["ir_version"], view["tuple"]["ir"])
                && same(handle["read_version"], view["tuple"]["read"]), "READ_HANDLE_VERSION_MISMATCH")
            try demand(handle["anchor"]["kind"].text == "asset" && request["selection"] == .null, "READ_HANDLE_ASSET_MISMATCH")
            anchor = ["kind": "asset"]
        } else {
            try demand(view["verification"]["mode"].text == "exact_selection" && handle["binding_kind"].text == "section_capture", "READ_HANDLE_UNTRUSTED")
            try demand(same(handle["asset"], view["asset"]) && same(handle["tuple"], view["tuple"]) && same(handle["origin"], recordOrigin), "READ_HANDLE_STALE")
            try demand(handle["anchor"]["kind"].text == "selection_set" && request["selection"] != .null
                && same(request["selection"]["asset_id"], view["asset"]["asset_id"])
                && same(request["selection"]["asset_version"], view["asset"]["asset_version"]), "READ_HANDLE_ASSET_MISMATCH")
            let ids = Set(request["selection"]["judgment_ids"].list.map { $0.text })
            let normalized = view["catalog"].list.filter { ids.contains($0["judgment_id"].text) }.map { $0["judgment_id"].text }
            var normalizedSelection = request["selection"]
            normalizedSelection["judgment_ids"] = .array(normalized.map { .string($0) })
            selection = normalizedSelection
            try demand(ids.count == normalized.count && same(normalizedSelection, handle["anchor"]["selection"]), "READ_HANDLE_ASSET_MISMATCH")
            anchor = handle["anchor"]
        }
        let targets: [J] = whole ? view["ir"]["expansion_targets"].list : view["expansion_targets"].list
        guard let proof = targets.first(where: { same($0["anchor"], anchor) && same($0["target"], handle["target"]) }),
              same(proof["scope"], handle["scope"]) else { throw PublicFailure("READ_HANDLE_SCOPE_MISMATCH") }
        var outRequest = request
        if let selection { outRequest["selection"] = selection }
        return Binding(request: outRequest, origin: recordOrigin, target: handle["target"], scope: proof["scope"].list,
                       anchor: anchor, sourceIdentity: snapshot.retainedSourceIdentity)
    }
    static func checkCapture(_ binding: Binding, _ capture: SectionFaces.Capture) throws {
        let identity = capture.identity
        try demand(capture.sourceIdentity() == binding.sourceIdentity
            && identity["input_byte_length"] == binding.origin["input_byte_length"]
            && same(identity["manifest_bytes_digest"], binding.origin["manifest_bytes_digest"])
            && same(identity["zip_directory_bytes_digest"], binding.origin["zip_directory_bytes_digest"]), "READ_HANDLE_STALE")
    }
}
