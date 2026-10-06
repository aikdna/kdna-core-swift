import Foundation

// The whole-read faces (sections-node.js executeSectionNode, read operation,
// whole_asset mode; @aikdna/kdna-core@0.36.0). Tokens are opaque final
// classes — the JS freeze + WeakMap discipline — and the phase order, the
// one-shot latch and the envelope codes follow the released flow
// point-by-point.
//
// The capture is the design-sanctioned in-memory-bytes variant: same
// metadata scan, same identity fields and consistency checks; file-read io
// batches have no bytes analogue (recorded; io is empty here).
//
// Declared gaps (both fail closed, never silently): partial modes
// (catalog / exact_selection / expand) return the released unsupported
// envelope until Stage B lands the partial flows; a signed asset fails at
// the integrity stage until the kdsig ed25519 stack is ported
// (SectionSignatures).
public final class KDNASectionSnapshot {
    let view: J
    fileprivate init(_ view: J) { self.view = view }
    public func inspect() -> KDNAValue { view }
}
public final class KDNAAdmittedSectionRequest {
    let data: J
    let digest: String
    fileprivate init(_ data: J, _ digest: String) { self.data = data; self.digest = digest }
}
public final class KDNASectionReadAuthority {
    let authorize: (J) async throws -> J?
    let policy: J
    fileprivate init(_ authorize: @escaping (J) async throws -> J?, _ policy: J) { self.authorize = authorize; self.policy = policy }
}
public enum SectionFaces {
    static func admitSectionRequest(_ candidate: J) throws -> KDNAAdmittedSectionRequest {
        _ = try SectionContract.validate("ReadRequest06Candidate", candidate)
        return KDNAAdmittedSectionRequest(candidate, sha(try KDNAJSON.canonical(candidate)))
    }
    static func createSectionReadAuthority(_ authorize: @escaping (J) async throws -> J?, signaturePolicy: J = SectionSignatures.defaultPolicy) throws -> KDNASectionReadAuthority {
        // The JS typeof-function check (SECTION_AUTHORITY_CALLBACK) is a
        // compile-time guarantee here; the policy validation is not.
        let policy = try SectionSignatures.policy(signaturePolicy)
        return KDNASectionReadAuthority(authorize, policy)
    }
    struct Capture {
        let bytes: [UInt8]
        let end: Int, cdStart: Int, cdSize: Int
        let rows: [(name: String, size: Int)]
        let manifestBytes: [UInt8]
        let directory: [UInt8]
        let footerObservation: [UInt8]
        let identity: J
        var consumed = false
        mutating func wholeAfterAuthorization() throws -> [UInt8] {
            try demand(!consumed)
            consumed = true
            try demand(bytes[cdStart..<cdStart + cdSize].elementsEqual(directory) && bytes[end...].elementsEqual(footerObservation))
            return bytes
        }
    }
    static func captureWhole(_ input: [UInt8]) throws -> Capture {
        let bytes = input
        try demand(bytes.count >= 22 && bytes.count <= SectionContainer.maximumBytes)
        func u32(_ at: Int) -> Int { (0..<4).reduce(0) { $0 | Int(bytes[at + $1]) << ($1 * 8) } }
        func u16(_ at: Int) -> Int { Int(bytes[at]) | Int(bytes[at + 1]) << 8 }
        var end = -1
        var cursor = bytes.count - 22
        while cursor >= max(0, bytes.count - 65557) {
            if u32(cursor) == 0x06054b50 && cursor + 22 + u16(cursor + 20) == bytes.count { end = cursor; break }
            cursor -= 1
        }
        try demand(end >= 0)
        let eocd = end
        try demand(u16(eocd + 4) == 0 && u16(eocd + 6) == 0 && u16(eocd + 8) == u16(eocd + 10))
        let count = u16(eocd + 10), cdSize = u32(eocd + 12), cdStart = u32(eocd + 16)
        try demand(count > 0 && count <= SectionContainer.countLimit && cdStart + cdSize == eocd)
        var rows: [(name: String, size: Int, method: Int, local: Int, start: Int, compressed: Int)] = []
        var names = Set<String>()
        var at = 0, total = 0
        for index in 0..<count {
            try demand(at + 46 <= cdSize)
            let record = cdStart + at
            try demand(u32(record) == 0x02014b50)
            let flags = u16(record + 8), method = u16(record + 10), compressed = u32(record + 20), size = u32(record + 24)
            let nameLength = u16(record + 28), extraLength = u16(record + 30), commentLength = u16(record + 32)
            let mode = u32(record + 38) >> 16, local = u32(record + 42)
            try demand(at + 46 + nameLength + extraLength + commentLength <= cdSize && nameLength > 0 && nameLength <= 4096)
            let nameBytes = Array(bytes[record + 46..<record + 46 + nameLength])
            guard let name = String(bytes: nameBytes, encoding: .utf8) else { throw PublicFailure("READ_CORE_INVALID") }
            let type = mode & 0o170000
            try demand(validEntry(name) && !names.contains(name) && flags & ~0x800 == 0 && u16(record + 34) == 0 && (type == 0 || type == 0o100000))
            names.insert(name)
            try demand(["mimetype", "kdna.json", "checksums.json", "signature.kdsig"].contains(name) || SectionContainer.packOrdinalDigits(name) != nil || name.hasPrefix("attachments/"))
            try demand(!name.hasPrefix("sections/") || method == 0)
            total += size
            try demand(size <= SectionContainer.entryLimit && !(compressed == 0 && size != 0) && !(compressed > 0 && size > compressed * SectionContainer.ratioLimit) && total <= SectionContainer.totalLimit)
            try demand(local + 30 <= cdStart)
            try demand(u32(local) == 0x04034b50 && u16(local + 6) == flags && u16(local + 8) == method && u32(local + 14) == u32(record + 16) && u32(local + 18) == compressed && u32(local + 22) == size && u16(local + 26) == nameLength)
            try demand(local + 30 + nameLength <= cdStart)
            try demand(bytes[local + 30..<local + 30 + nameLength].elementsEqual(nameBytes))
            let start = local + 30 + nameLength + u16(local + 28)
            try demand(start + compressed <= cdStart)
            if index == 0 { try demand(name == "mimetype" && local == 0 && method == 0) }
            rows.append((name: name, size: size, method: method, local: local, start: start, compressed: compressed))
            at += 46 + nameLength + extraLength + commentLength
        }
        try demand(at == cdSize)
        try demand(rows.contains { $0.name == "kdna.json" } && rows.contains { $0.name == "mimetype" })
        let directory = Array(bytes[cdStart..<cdStart + cdSize])
        let manifestRow = rows.first { $0.name == "kdna.json" }!
        let manifestRaw = Array(bytes[manifestRow.start..<manifestRow.start + manifestRow.compressed])
        let manifestBytes: [UInt8]
        if manifestRow.method == 0 { manifestBytes = manifestRaw }
        else if manifestRow.method == 8 { manifestBytes = try PublicContainer.decompress(manifestRaw, maximum: SectionContainer.entryLimit) }
        else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        let mimetypeRow = rows.first { $0.name == "mimetype" }!
        let mimetypeBytes = Array(bytes[mimetypeRow.start..<mimetypeRow.start + mimetypeRow.compressed])
        try demand(String(bytes: mimetypeBytes, encoding: .utf8) == "application/vnd.kdna.asset")
        let identity: J = ["capture_id": .string("capture:" + UUID().uuidString.lowercased()), "input_byte_length": .number(Double(bytes.count)),
                           "manifest_bytes_digest": .string(sha(Data(manifestBytes))), "zip_directory_bytes_digest": .string(sha(Data(directory))),
                           "identity_scope": "observed_metadata_and_loaded_sections_only", "table_frames": .array([])]
        return Capture(bytes: bytes, end: end, cdStart: cdStart, cdSize: cdSize,
                       rows: rows.map { (name: $0.name, size: $0.size) }, manifestBytes: manifestBytes,
                       directory: directory, footerObservation: Array(bytes[end...]), identity: identity)
    }
    static let unsupportedCodes = ["CONTAINER_COMMENT_CAPTURE_UNIMPLEMENTED", "PROTECTION_BINDING_UNIMPLEMENTED", "PARTIAL_SEMANTIC_PROOF_UNAVAILABLE", "EXPAND_INTEGRATION_UNIMPLEMENTED", "CHECKSUMS_PROFILE_UNSUPPORTED", "CHECKSUMS_SCOPED_PROOF_UNIMPLEMENTED", "SIGNATURE_PROFILE_UNSUPPORTED"]
    static func classify(_ code: String) -> String { unsupportedCodes.contains(code) ? "unsupported" : "rejected" }
    /// Accepted reads carry the opaque snapshot token beside the envelope;
    /// rejected and unsupported reads carry the full closed envelope.
    public struct ReadOutcome {
        public let envelope: KDNAValue
        public let snapshot: KDNASectionSnapshot?
    }
    public static func readWhole(_ bytes: [UInt8], _ admitted: KDNAAdmittedSectionRequest, _ authority: KDNASectionReadAuthority) async -> ReadOutcome {
        var stage = "input"
        func failure(_ status: String, _ reason: String, _ diagnosticField: String? = nil, _ diagnosticSubject: String? = nil) -> ReadOutcome {
            let contractId = (try? SectionContract.loadedContract.get()["module"]["id"]) ?? .null
            let diagnostic: J = (diagnosticField == nil && diagnosticSubject == nil)
                ? .null
                : ["field": diagnosticField.map { .string($0) } ?? .null, "subject": diagnosticSubject.map { .string($0) } ?? .null]
            let value: J = ["contract": contractId, "request_id": admitted.data["request_id"],
                            "status": .string(status), "reason": .string(reason), "stage": .string(stage), "io": .array([]),
                            "diagnostic": diagnostic]
            // Self-check against the closed envelope; a mismatch is a port bug,
            // not a caller-visible condition.
            try? SectionContract.validate(status == "unsupported" ? "SectionAdmissionUnsupported06" : "SectionAdmissionRejected06", value)
            return ReadOutcome(envelope: value, snapshot: nil)
        }
        do {
            let request = admitted.data
            if request["mode"].text != "whole_asset" {
                return failure("unsupported", request["mode"].text == "expand" ? "EXPAND_INTEGRATION_UNIMPLEMENTED" : "PARTIAL_SEMANTIC_PROOF_UNAVAILABLE")
            }
            var capture = try captureWhole(bytes)
            stage = "metadata"
            let manifest = try SectionManifest.load(capture.manifestBytes)
            if SectionManifest.protectionDeclared(manifest) {
                return failure("unsupported", "PROTECTION_BINDING_UNIMPLEMENTED")
            }
            let intent = try SectionSignatures.intent(capture.rows)
            let authorization: J = ["request": request, "request_digest": .string(admitted.digest), "capture": capture.identity,
                                    "manifest_identity": ["asset_id": manifest["asset_id"], "asset_version": manifest["version"], "judgment_version": manifest["judgment_version"]],
                                    "mode": "whole_asset", "operation": "read", "signature_policy": authority.policy,
                                    "signature_policy_digest": .string(sha(try KDNAJSON.canonical(authority.policy))),
                                    "signature_read_intent": intent, "signature_read_intent_digest": .string(sha(try KDNAJSON.canonical(intent)))]
            stage = "authorization"
            let grant: J?
            do { grant = try await authority.authorize(authorization) } catch { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            try demand(grant == .some(.bool(true)), "SECTION_PERMISSION_DENIED")
            stage = "content"
            let wholeBytes = try capture.wholeAfterAuthorization()
            let entries = try SectionContainer.parse(Data(wholeBytes))
            if entries.first(where: { $0.name == "kdna.json" })?.bytes != capture.manifestBytes { throw PublicFailure("SECTION_CAPTURE_CHANGED") }
            let restored = try SectionFrameGraph.restoreWholeFrames(entries, manifest)
            let payload = try SectionDigests.reconstructPayload(restored.ir)
            stage = "semantic"
            _ = try SectionDigests.validateDecodedPayload(manifest, payload)
            let entryMap = Dictionary(uniqueKeysWithValues: entries.map { (KDNAKey($0.name), Data($0.bytes)) })
            var derived = try CanonicalIR.buildIR(manifest, payload, entryMap)
            derived["tuple"] = try SectionContract.loadedContract.get()["module"]["versionTuple"]
            try demand(sha(try KDNAJSON.canonical(derived)) == sha(try KDNAJSON.canonical(restored.ir)), "SECTION_DERIVED_IR_MISMATCH")
            stage = "integrity"
            let observations = try SectionDigests.observeWhole(wholeBytes, entries, manifest, restored.packNames)
            try SectionDigests.assertContentBindings(manifest, observations.C)
            let captureId = capture.identity["capture_id"].text
            let checksumIntegrity = try SectionChecksums.verifyChecksums(entries, observations, captureId, admitted.digest)
            let signatureIntegrity = try SectionSignatures.verify(entries, authority.policy, captureId, admitted.digest, intent)
            var tableFrames: [J] = []
            for section in restored.checkedSections where section["section_id"].text.hasPrefix("table:") { tableFrames.append(section) }
            var captureVerification = capture.identity
            captureVerification["table_frames"] = .array(tableFrames)
            let verification: J = ["signature_integrity": signatureIntegrity, "checksum_integrity": checksumIntegrity,
                                   "capture": captureVerification, "request_digest": .string(admitted.digest),
                                   "checked_sections": .array(restored.checkedSections), "unchecked_sections": .array([]),
                                   "routing_integrity": "checked", "runtime_entry_digest": observations.E,
                                   "whole_container_digest": ["profile": "kdna.digest-basis.container-bytes/0.2.0", "status": "verified", "digest": .string(observations.A)],
                                   "whole_content_digest": ["profile": "kdna.digest-basis.content-tree/0.2.0", "status": "verified", "digest": .string(observations.C)],
                                   "ir_digest": ["profile": "CanonicalIR:SHA-256(RFC8785):existing-digestCanonical", "status": "verified", "digest": .string(sha(try KDNAJSON.canonical(derived)))],
                                   "mode": "whole_asset", "semantic_status": "verified_whole_graph"]
            let expectedC: J = manifest["content_digest"] != .null ? manifest["content_digest"] : (manifest["authoring"]["content_digest"] != .null ? manifest["authoring"]["content_digest"] : .null)
            let cSource: J = manifest["content_digest"] != .null
                ? ["kind": "manifest_declaration", "source_id": "kdna.json"]
                : ["kind": "manifest_declaration", "source_id": "kdna.json/authoring/content_digest"]
            var eEvidence = PublicDigests.evidence("E", observations.E["digest"].text,
                                                   expected: checksumIntegrity["status"].text == "verified_document_2" ? checksumIntegrity["expected_entry_set_digest"] : .null,
                                                   expectedSource: ["kind": "checksums_declaration", "source_id": "checksums.json"])
            eEvidence["profile_version"] = "0.3.0-candidate"
            let digests: J = ["A": PublicDigests.evidence("A", observations.A),
                              "C": PublicDigests.evidence("C", observations.C, expected: expectedC, expectedSource: cSource),
                              "E": eEvidence]
            let data: J = ["digests": digests, "snapshot_id": .string("section-snapshot:" + UUID().uuidString.lowercased()),
                           "tuple": try SectionContract.loadedContract.get()["module"]["versionTuple"],
                           "asset": payload["asset"], "ir": derived, "runtime_entry_names": observations.E["member_names"],
                           "verification": verification]
            _ = try SectionContract.validate("WholeSectionSnapshotData06", data)
            let envelope: J = ["status": "accepted", "io": .array([]), "input_byte_length": .number(Double(wholeBytes.count))]
            return ReadOutcome(envelope: envelope, snapshot: KDNASectionSnapshot(data))
        } catch let failureValue as PublicFailure {
            return failure(classify(failureValue.code), failureValue.code, failureValue.field, failureValue.subject)
        } catch {
            return failure("rejected", "READ_CORE_CAPABILITY_UNAVAILABLE")
        }
    }
}
