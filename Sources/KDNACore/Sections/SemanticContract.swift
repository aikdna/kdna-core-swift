import Foundation

// The 0.5.x-generation contract (tuple container 0.5.0 / payload_version
// 0.5.1), the generation the sections chain's payload and IR semantics run
// against: `validate('Payload', ...)` in semantic-admission.js and
// `validate('CanonicalIR', ...)` in canonical-ir.js both resolve against
// this file (validate.js loads generated-contract.json).
//
// The package's bundled generated-contract.json is the 0.2.0 generation and
// drives the previous container line; this resource is the released 0.36.0
// file as a mechanical SHA-pinned mirror (byte-identical). Both generations
// coexist deliberately — see the design note's generation-gap finding.
//
// Named difference (recorded, not hidden): the Node rejection carries an
// Ajv field pointer (diagnostic.field, e.g. "/payload/asset_capability");
// this port reports the code without the pointer until a consumer needs it.
enum SemanticContract {
    static let resourceSHA = "b405bdb007ce18e144c607d92af4127540119c6d302724c313ae6bb0b72ab915"
    static let loadedContract: Result<J, Error> = Result {
        guard let url = Bundle.module.url(forResource: "generated-contract-0.5", withExtension: "json", subdirectory: "Schemas") else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        let data = try Data(contentsOf: url)
        try demand(sha(data) == "sha256:" + resourceSHA, "READ_CORE_CAPABILITY_UNAVAILABLE")
        let contract = try KDNAJSON.parse(data)
        for shape in contract["types"].fields.values { try PublicSchema.checkKeywords(shape) }
        return contract
    }
    static func validate(_ name: String, _ value: J) throws -> J {
        let contract = try loadedContract.get(), types = contract["types"]
        try demand(PublicSchema.matches(value, types[name], types), "READ_CORE_INVALID")
        try PublicSchema.scalars(value, types[name], types)
        return value
    }
}
