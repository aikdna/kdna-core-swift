import Foundation

// The expansion origin registry (section-expansion.js retain/originValue,
// @aikdna/kdna-core@0.36.0): an accepted exact_selection retains the origin
// record for a later expand binding. The released code uses a WeakMap keyed
// by the opaque snapshot token; the port keeps the record on the snapshot
// object itself (the same lifetime semantics without a global map).
enum SectionExpansion {
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
}
