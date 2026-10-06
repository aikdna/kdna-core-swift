import Foundation

// The sections contract as a loaded, keyword-checked, SHA-pinned mechanical
// mirror of the released @aikdna/kdna-core@0.36.0
// src/public-contract/sections/contract.json (byte-identical; the pin fails
// closed and every type is keyword-checked at load), plus the generic
// `validate` equivalent of section-common.js: schema shape first
// (SECTION_TYPED_SHAPE), then the scalar pass for Identifier / EntryName /
// RuntimeMandatoryEntryName / Timestamp (READ_CORE_INVALID).
enum SectionContract {
    static let resourceSHA = "a22a101db40b93d6e3817f8b9c30830e0a6526b2f81f6aa8c80b3ae80e0aaa20"
    static let loadedContract: Result<J, Error> = Result {
        guard let url = Bundle.module.url(forResource: "sections-contract", withExtension: "json", subdirectory: "Schemas") else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        let data = try Data(contentsOf: url)
        try demand(sha(data) == "sha256:" + resourceSHA, "READ_CORE_CAPABILITY_UNAVAILABLE")
        let contract = try KDNAJSON.parse(data)
        for shape in contract["types"].fields.values { try PublicSchema.checkKeywords(shape) }
        return contract
    }
    static func validate(_ name: String, _ value: J) throws -> J {
        let contract = try loadedContract.get(), types = contract["types"]
        try demand(PublicSchema.matches(value, types[name], types), "SECTION_TYPED_SHAPE")
        try PublicSchema.scalars(value, types[name], types)
        return value
    }
}
