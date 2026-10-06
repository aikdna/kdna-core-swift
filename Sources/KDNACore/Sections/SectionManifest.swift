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
// src/public-contract/sections/contract.json, carried as a mechanical
// SHA-pinned mirror in Resources/Schemas (byte-identical to the released
// file; the pin fails closed, and every type is keyword-checked against the
// implemented schema subset at load).
enum SectionManifest {
    static let resourceSHA = "a22a101db40b93d6e3817f8b9c30830e0a6526b2f81f6aa8c80b3ae80e0aaa20"
    static let loadedContract: Result<J, Error> = Result {
        guard let url = Bundle.module.url(forResource: "sections-contract", withExtension: "json", subdirectory: "Schemas") else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        let data = try Data(contentsOf: url)
        try demand(sha(data) == "sha256:" + resourceSHA, "READ_CORE_CAPABILITY_UNAVAILABLE")
        let contract = try KDNAJSON.parse(data)
        for shape in contract["types"].fields.values { try PublicSchema.checkKeywords(shape) }
        return contract
    }
    static func validate(_ manifest: J) throws -> J {
        let contract = try loadedContract.get(), types = contract["types"]
        try demand(PublicSchema.matches(manifest, types["Manifest06Candidate"], types), "SECTION_TYPED_SHAPE")
        try PublicSchema.scalars(manifest, types["Manifest06Candidate"], types)
        return manifest
    }
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
