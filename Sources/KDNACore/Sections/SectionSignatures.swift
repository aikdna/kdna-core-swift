import Foundation

// The kdsig signature domain (section-signatures.js, @aikdna/kdna-core@0.36.0):
// policy validation, the read intent and the whole-read verification path.
// Unsigned assets resolve to the 'absent' status (or SECTION_SIGNATURE_REQUIRED
// when the policy demands a signature). The signed branch needs the original
// kdsig ed25519 helpers (protection-integrity.js + signature.js); a signed
// asset fails closed here rather than being silently treated as unsigned —
// recorded as the remaining named gap of the faces package.
enum SectionSignatures {
    static let profile = "kdsig.ed25519", version = "0.1.0"
    static let defaultPolicy: J = ["requireSignature": false, "expectedPublicKeyHex": nil]
    static func invalid(_ code: String = "SECTION_SIGNATURE_INVALID", _ field: String = "/signature.kdsig", _ subject: String? = nil) throws -> Never {
        let safeSubject = subject.flatMap { !$0.isEmpty && scalar($0, maximum: 256, controls: false) ? $0 : nil }
        throw PublicFailure(code, field: field, subject: safeSubject)
    }
    static func policy(_ candidate: J = defaultPolicy) throws -> J { try SectionContract.validate("SectionSignaturePolicy06", candidate) }
    static func excluded(_ name: String) -> Bool { [".DS_Store", "build-receipt.json", "signature.kdsig"].contains(name) || name.hasPrefix("reports/") }
    static func intent(_ rows: [(name: String, size: Int)]) throws -> J {
        guard let signature = rows.first(where: { $0.name == "signature.kdsig" }) else {
            return try SectionContract.validate("SectionSignatureReadIntent06", ["operation": "none"])
        }
        var result: J = [:]
        result["operation"] = "verify_complete_original_kdsig_domain"
        result["signature_member"] = ["name": "signature.kdsig", "bytes": J.number(Double(signature.size))]
        var coveredRows = rows.filter { !excluded($0.name) }
        coveredRows.sort { SectionFrameGraph.utf8Less($0.name, $1.name) }
        var covered: [J] = []
        for row in coveredRows {
            var member: J = [:]
            member["name"] = .string(row.name)
            member["bytes"] = .number(Double(row.size))
            covered.append(member)
        }
        result["covered_members"] = .array(covered)
        var excludedNames = rows.filter { excluded($0.name) }.map { $0.name }
        excludedNames.sort(by: SectionFrameGraph.utf8Less)
        result["excluded_members"] = .array(excludedNames.map { J.string($0) })
        result["profile"] = .string(profile)
        result["profile_version"] = .string(version)
        return try SectionContract.validate("SectionSignatureReadIntent06", result)
    }
    static func verify(_ entries: [SectionContainer.Entry], _ signaturePolicy: J, _ captureId: String, _ requestDigest: String, _ readIntent: J) throws -> J {
        let common: J = ["policy": signaturePolicy, "policy_digest": .string(sha(try KDNAJSON.canonical(signaturePolicy))),
                         "read_intent_digest": .string(sha(try KDNAJSON.canonical(readIntent))),
                         "capture_id": .string(captureId), "request_digest": .string(requestDigest)]
        guard entries.contains(where: { $0.name == "signature.kdsig" }) else {
            if readIntent["operation"].text != "none" { throw PublicFailure("SECTION_SIGNATURE_INTENT_MISMATCH") }
            if signaturePolicy["requireSignature"].boolean || signaturePolicy["expectedPublicKeyHex"] != .null { try invalid("SECTION_SIGNATURE_REQUIRED") }
            var result = common
            result["status"] = "absent"
            return try SectionContract.validate("SectionSignatureVerification06", result)
        }
        throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE")
    }
}
