import Foundation

// The 0.6 manifest view: kdna.json is strict JSON validated closed against
// the sections contract's Manifest06Candidate type, the way
// section-common.js `validate` does it — schema shape first
// (SECTION_TYPED_SHAPE), then the scalar pass for Identifier / EntryName /
// RuntimeMandatoryEntryName / Timestamp (READ_CORE_INVALID). Parse-level
// failures keep the Node split observable: scanner rejects surface their
// codes (READ_INPUT_INVALID et al.), while the malformed-escape class —
// which Node's parseJson raises as a raw JSON.parse SyntaxError — maps to
// READ_CORE_CAPABILITY_UNAVAILABLE through the sections catch-all.
//
// Authority: @aikdna/kdna-core@0.36.0
// src/public-contract/sections/contract.json (see SectionContract).
enum SectionManifest {
    static func validate(_ manifest: J) throws -> J { try SectionContract.validate("Manifest06Candidate", manifest) }
    static func load(_ bytes: [UInt8]) throws -> J {
        let manifest: J
        do { manifest = try KDNAJSON.parse(Data(bytes)) }
        catch is StrictJSONSyntaxFailure { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        return try validate(manifest)
    }

    // Downstream projections (each has a named consumer in the ported flow:
    // frame graph, observeE, the admission protection gate, identity, and the
    // C-digest binding).
    static func representationMetadata(_ manifest: J) -> J { manifest["representation_metadata"] }
    static func payloadTables(_ manifest: J) -> [J] { manifest["payload"]["tables"].list }
    static func runtimeMandatoryEntries(_ manifest: J) -> [String] { manifest["runtime"]["mandatory_entries"].list.map { $0.text } }
    static func protectionDeclared(_ manifest: J) -> Bool {
        manifest["payload"]["encrypted"].boolean || manifest.has("encryption") || manifest.has("entitlement")
    }
    static func assetIdentity(_ manifest: J) -> (assetId: String, assetVersion: String, judgmentVersion: String) {
        (manifest["asset_id"].text, manifest["version"].text, manifest["judgment_version"].text)
    }
    static func declaredContentDigests(_ manifest: J) -> [String] {
        [manifest["content_digest"], manifest["authoring"]["content_digest"]].filter { $0 != .null && !$0.text.isEmpty }.map { $0.text }
    }
}
