import Foundation
import CryptoKit

// The loaded-validation inputs (section-loaded-validation.js,
// @aikdna/kdna-core@0.36.0): the interpretation-inputs read over the topic
// frames — the scanner retains the method/extensions/result_contract/
// formation_rule/parent_ref/lifecycle subtrees and every extension position,
// so those bytes are read and hashed while the rest of the body text stays
// unobserved. The schema/scalar/interpretation passes of this module land
// with the fixed-point closure.
enum SectionLoadedValidation {
    /// The released signature takes `structure` but does not consult it; the
    /// parameter is kept for call-site parity.
    static func readInterpretationInputs(_ capture: inout SectionFaces.Capture, _ layout: SectionLayout.Layout, _ structure: SectionStructure.Inspection?) throws -> J {
        var judgments: [String: J] = [:]
        var frames: [J] = []
        for row in layout.ordered {
            if row["kind"].text != "topic" { continue }
            let length = Int(row["length_bytes"].numeric)
            var observed = SHA256()
            let scan = try capture.structureAfterAuthorization(row["member"].text, Int(row["offset_bytes"].numeric), length) { read in
                try SectionStructureScanner.scanFrame(length, true) { innerOffset, count, _ in
                    let bytes = try read(innerOffset, count)
                    var header = Data()
                    for shift in stride(from: 56, through: 0, by: -8) { header.append(UInt8(truncatingIfNeeded: UInt64(innerOffset) >> UInt64(shift))) }
                    for shift in stride(from: 56, through: 0, by: -8) { header.append(UInt8(truncatingIfNeeded: UInt64(count) >> UInt64(shift))) }
                    observed.update(data: header)
                    observed.update(data: Data(bytes))
                    return bytes
                }
            }
            try demand(scan.partial["kind"].text == "topic" && scan.partial["section_id"].text == row["section_id"].text, "SECTION_INTERPRETATION_FRAME")
            let records = scan.partial["records"].list.filter { $0["target"]["kind"].text == "judgment" }
            try demand(records.count == 1 && records[0]["target"]["id"].text == String(row["section_id"].text.dropFirst(6))
                && records[0]["value"]["id"].text == records[0]["target"]["id"].text, "SECTION_INTERPRETATION_JUDGMENT")
            judgments[records[0]["value"]["id"].text] = records[0]["value"]
            frames.append(["section_id": row["section_id"], "member": row["member"], "offset_bytes": row["offset_bytes"], "length_bytes": row["length_bytes"],
                           "observed_ranges_digest": .string("sha256:" + observed.finalize().map { String(format: "%02x", $0) }.joined()),
                           "observed_read_bytes": .number(Double(scan.readBytes)), "read_calls": .number(Double(scan.reads.count)),
                           "skipped_text_bytes": .number(Double(scan.skippedTextBytes)),
                           "frame_digest_status": "not_checked", "unread_text_status": "not_checked"])
        }
        let ordered = layout.meta["catalog"].list.map { judgments[$0["judgment_id"].text] }
        try demand(ordered.allSatisfy { $0 != nil }, "SECTION_INTERPRETATION_SET")
        return ["judgments": .array(ordered.map { $0! }), "frames": .array(frames)]
    }
    /// validateAuthored (section-loaded-validation.js): validate a value
    /// against an embedded shape whose $refs resolve into the 0.5 contract,
    /// then the shape-level scalar pass. The Node rejection carries the Ajv
    /// field pointer (path + instancePath + missing property).
    static func validateAuthored(_ shape: J, _ value: J, _ path: String) throws {
        let contract = try SemanticContract.loadedContract.get(), types = contract["types"]
        if let failure = PublicSchema.firstError(value, shape, types, "") {
            let missing = failure.missing.map { "/" + $0 } ?? ""
            throw PublicFailure("READ_CORE_INVALID", field: path + failure.path + missing, subject: nil)
        }
        try PublicSchema.scalars(value, shape, types)
    }
    /// validateLoadedSchema: the payload's required fields, every non-judgment
    /// field against its Payload property shape, the loaded judgments against
    /// the Judgment shape, the interpretation judgments' authored children,
    /// then the scoped cross-entry obligations.
    static func validateLoadedSchema(_ payload: J, _ loadedJudgments: Set<String>, _ interpretation: J) throws {
        let contract = try SemanticContract.loadedContract.get(), types = contract["types"]
        let payloadShape = types["Payload"]
        for key in payloadShape["required"].list where !["asset_capability", "judgments"].contains(key.text) {
            guard payload.has(key.text) else { throw PublicFailure("SECTION_PAYLOAD_REQUIRED") }
        }
        for key in payload.fields.keys.map({ $0.text }) where key != "judgments" && key != "asset_capability" {
            guard payloadShape["properties"].has(key) else { throw PublicFailure("SECTION_PAYLOAD_FIELD") }
            try validateAuthored(payloadShape["properties"][key], payload[key], "/payload/" + key)
        }
        for (i, judgment) in payload["judgments"].list.enumerated() where loadedJudgments.contains(judgment["id"].text) {
            try validateAuthored(["$ref": "#/$defs/Judgment"], judgment, "/payload/judgments/\(i)")
        }
        let judgmentShape = types["Judgment"]
        for (i, judgment) in interpretation["judgments"].list.enumerated() {
            for key in ["method", "extensions", "result_contract", "formation_rule", "parent_ref", "lifecycle"] where judgment.has(key) {
                let child = judgmentShape["properties"][key]
                guard child != .null else { throw PublicFailure("SECTION_ORIGINAL_TYPE_MISSING") }
                try validateAuthored(child, judgment[key], "/payload/judgments/\(i)/" + key)
            }
        }
        try CrossEntry.assertScopedPayload(payload, contract["core_terms"], loadedJudgments, interpretation["judgments"].list)
    }
}
