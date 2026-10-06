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
    // MARK: - Scoped (partial) flow — section-signatures.js
    /// authorizationContext: the whole-read face builds this inline; the
    /// partial flows share it with their own mode.
    static func authorizationContext(_ request: J, _ requestDigest: String, _ capture: SectionFaces.Capture, _ manifest: J, _ mode: String, _ signaturePolicy: J) throws -> J {
        let readIntent = try intent(capture.rows.map { (name: $0.name, size: $0.size) })
        return ["request": request, "request_digest": .string(requestDigest), "capture": capture.identity,
                "manifest_identity": ["asset_id": manifest["asset_id"], "asset_version": manifest["version"], "judgment_version": manifest["judgment_version"]],
                "mode": .string(mode), "operation": "read", "signature_policy": signaturePolicy,
                "signature_policy_digest": .string(sha(try KDNAJSON.canonical(signaturePolicy))),
                "signature_read_intent": readIntent,
                "signature_read_intent_digest": .string(sha(try KDNAJSON.canonical(readIntent)))]
    }
    /// readScoped: the signature members a signed intent requires; unsigned
    /// intents contribute nothing (the Node flow reads no extra bytes).
    static func readScoped(_ capture: inout SectionFaces.Capture, _ readIntent: J) throws -> [String: [UInt8]]? {
        if readIntent["operation"].text == "none" { return nil }
        var entries: [String: [UInt8]] = [:]
        let signature = readIntent["signature_member"]
        if signature["bytes"].numeric > 1048576 { try invalid() }
        entries[signature["name"].text] = try capture.signatureMemberAfterAuthorization(signature["name"].text)
        for row in readIntent["covered_members"].list {
            let name = row["name"].text
            let bytes = name == "kdna.json" ? capture.manifestBytes : try capture.signatureMemberAfterAuthorization(name)
            try demand(bytes.count == Int(row["bytes"].numeric), "SECTION_SIGNATURE_INTENT_MISMATCH")
            entries[name] = bytes
        }
        try demand(readIntent["excluded_members"].list.allSatisfy { $0.text == "signature.kdsig" }, "SECTION_SIGNATURE_INTENT_MISMATCH")
        try capture.assertUnchanged()
        return entries
    }
    /// completeScoped: the scoped checksum completion plus the signature
    /// verification over the scoped member set. A signed asset still fails
    /// closed at `verify` until the kdsig ed25519 stack is ported (the one
    /// declared gap this flow keeps).
    static func completeScoped(_ capture: inout SectionFaces.Capture, _ checksumState: J?, _ requestDigest: String, _ signaturePolicy: J, _ readIntent: J) throws -> J {
        let actual = try readScoped(&capture, readIntent)
        var checksums = try SectionChecksums.completeScopedChecksums(&capture, checksumState, requestDigest, actual)
        let entries: [SectionContainer.Entry] = (actual ?? [:]).map { SectionContainer.Entry(name: $0.key, bytes: $0.value, mode: 0) }
        checksums["signature_integrity"] = try verify(entries, signaturePolicy, capture.identity["capture_id"].text, requestDigest, readIntent)
        try capture.assertUnchanged()
        return checksums
    }
}
