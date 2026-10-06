import Foundation
import CryptoKit

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
        // The signed branch (section-signatures.js parse/domain/verify plus
        // the kdsig helpers in signature.js and protection-integrity.js): the
        // bundle parse pre-checks, the intent comparison, the policy pin, the
        // per-member signature-basis domain and the Ed25519 verification.
        let raw = entries.first { $0.name == "signature.kdsig" }!.bytes
        let bundle = try parseBundle(raw)
        let actualIntent = try intent(entries.map { (name: $0.name, size: $0.bytes.count) })
        try demand(sha(try KDNAJSON.canonical(actualIntent)) == sha(try KDNAJSON.canonical(readIntent)), "SECTION_SIGNATURE_INTENT_MISMATCH")
        if signaturePolicy["expectedPublicKeyHex"] != .null && !exact(bundle["public_key"].text, signaturePolicy["expectedPublicKeyHex"].text) {
            try invalid("SECTION_SIGNATURE_PIN_MISMATCH", "/signature.kdsig/public_key")
        }
        var domainRows: [String] = [], members: [J] = []
        var excludedNames = entries.map { $0.name }.filter { excluded($0) }
        excludedNames.sort(by: SectionFrameGraph.utf8Less)
        var names = entries.map { $0.name }.filter { !excluded($0) }
        names.sort(by: SectionFrameGraph.utf8Less)
        for name in names {
            guard let entry = entries.first(where: { $0.name == name }) else { continue }
            let row: String
            do { row = try signatureBasisRow(name, entry.bytes) }
            catch {
                if name.lowercased().hasSuffix(".json") { try invalid("SECTION_SIGNATURE_INVALID", "/" + name, name) }
                throw error
            }
            domainRows.append(row)
            members.append(["name": .string(name), "bytes": .number(Double(entry.bytes.count)),
                            "raw_digest": .string(sha(Data(entry.bytes))),
                            "signature_basis_digest": .string("sha256:" + String(row.suffix(64)))])
        }
        let observed = sha(Data(domainRows.joined(separator: "\n").utf8))
        do { try verifyBundle(raw, observed) }
        catch let failureValue as PublicFailure where failureValue.code == "KDNA_INTEGRITY_SIGNATURE_FAILED" { try invalid() }
        var result = common
        result["status"] = signaturePolicy["expectedPublicKeyHex"] == .null ? .string("verified_self_key") : .string("verified_pinned_key")
        result["profile"] = .string(profile)
        result["profile_version"] = .string(version)
        result["algorithm"] = "ed25519"
        result["signature_document_digest"] = .string(sha(Data(raw)))
        result["expected_signature_content_digest"] = bundle["content_digest"]
        result["observed_signature_content_digest"] = .string(observed)
        result["public_key"] = bundle["public_key"]
        result["key_fingerprint"] = .string(try keyFingerprint(bundle["public_key"].text))
        result["members"] = .array(members)
        result["excluded_members"] = .array(excludedNames.map { .string($0) })
        return try SectionContract.validate("SectionSignatureVerification06", result)
    }
    // MARK: - The kdsig helpers (signature.js + protection-integrity.js)
    static func hexBytes(_ hex: String, _ count: Int) -> [UInt8]? {
        guard hex.count == count * 2, hex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { return nil }
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }
    static func keyFingerprint(_ publicKeyHex: String) throws -> String {
        guard let raw = hexBytes(publicKeyHex, 32) else { throw PublicFailure("KDNA_SIGNATURE_KEY_INVALID") }
        return sha(Data(raw))
    }
    /// The section-level bundle parse pre-checks then the kdsig parse.
    static func parseBundle(_ raw: [UInt8]) throws -> J {
        if raw.count > 1048576 { try invalid() }
        let value: J
        do { value = try KDNAJSON.parse(Data(raw)) }
        catch is PublicFailure { try invalid() }
        catch is StrictJSONSyntaxFailure { try invalid() }
        let fields = ["algorithm", "content_digest", "profile", "profile_version", "public_key", "signature"]
        guard value.fields.count == fields.count, fields.allSatisfy({ value.has($0) && !value[$0].text.isEmpty }),
              value["content_digest"].text.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil,
              hexBytes(value["public_key"].text, 32) != nil,
              hexBytes(value["signature"].text, 64) != nil else { try invalid() }
        if value["profile"].text != profile || value["profile_version"].text != version || value["algorithm"].text != "ed25519" {
            try invalid("SIGNATURE_PROFILE_UNSUPPORTED")
        }
        return value
    }
    /// protection-integrity.signatureContentPreimage for one member: JSON
    /// members are re-canonicalized (kdna.json additionally drops the digest
    /// fields); the row is name + ':' + the member digest hex.
    static func signatureBasisRow(_ name: String, _ bytes: [UInt8]) throws -> String {
        var member = bytes
        if name.lowercased().hasSuffix(".json") {
            var value = try KDNAJSON.parse(Data(bytes))
            if name == "kdna.json" {
                for key in ["asset_digest", "container_sha256", "content_digest", "_source"] { value.remove(key) }
                if case .object = value["authoring"] { value["authoring"].remove("content_digest") }
            }
            member = [UInt8](try KDNAJSON.canonical(value))
        }
        return name + ":" + String(sha(Data(member)).dropFirst(7))
    }
    /// signature.verifySignatureBundle: the content-digest equality and the
    /// Ed25519 verification over the domain-separated signing payload.
    static func verifyBundle(_ raw: [UInt8], _ contentDigest: String) throws {
        let bundle = try parseBundle(raw)
        guard exact(bundle["content_digest"].text, contentDigest) else { throw PublicFailure("KDNA_INTEGRITY_SIGNATURE_FAILED") }
        guard let publicKeyBytes = hexBytes(bundle["public_key"].text, 32), let signatureBytes = hexBytes(bundle["signature"].text, 64),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKeyBytes)) else {
            throw PublicFailure("KDNA_INTEGRITY_SIGNATURE_FAILED")
        }
        let payload = Data("\(profile):\(version):\(contentDigest)".utf8)
        guard publicKey.isValidSignature(Data(signatureBytes), for: payload) else {
            throw PublicFailure("KDNA_INTEGRITY_SIGNATURE_FAILED")
        }
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
