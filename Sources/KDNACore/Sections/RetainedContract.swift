import Foundation

// The retained-read contract (retained/contract.json,
// @aikdna/kdna-core@0.36.0): the closed type set for the retained request
// admission, the preparation data, the authority context and the read
// envelopes. Byte-identical SHA-pinned mirror, loaded through the same
// schema engine as the sections contract.
enum RetainedContract {
    static let resourceSHA = "188b4de851b696a21153b4a3f45fb4a1f6ef9d33cdd279e3d6aa1dc61023278c"
    static let loadedContract: Result<J, Error> = Result {
        guard let url = Bundle.module.url(forResource: "retained-contract", withExtension: "json", subdirectory: "Schemas") else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
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
