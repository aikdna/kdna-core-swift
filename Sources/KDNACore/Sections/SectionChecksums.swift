import Foundation

// The checksums document (section-checksums.js, @aikdna/kdna-core@0.36.0):
// the whole-read verification path — absent, or a verified
// kdna.checksums.document/2 with the first structural difference surfaced
// as SECTION_CHECKSUMS_INVALID with its field pointer and entry subject.
enum SectionChecksums {
    static let profile = "kdna.checksums.document/2", version = "2.0.0-candidate"
    static func invalid(_ field: String = "/checksums.json", _ subject: String? = nil) throws -> Never {
        let safe = subject.flatMap { !$0.isEmpty && scalar($0, maximum: 256, controls: false) ? $0 : nil }
        throw PublicFailure("SECTION_CHECKSUMS_INVALID", field: field, subject: safe)
    }
    static func documentFor(_ entries: [SectionContainer.Entry], _ observations: (A: String, C: String, E: J)) -> J {
        let memberNames = observations.E["member_names"].list.map { $0.text }
        let byName = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0.bytes) })
        return ["profile": .string(profile), "profile_version": .string(version), "algorithm": "sha256",
                "digest_profile": "kdna.digest-basis.runtime-entry-set", "digest_profile_version": "0.3.0-candidate",
                "covered_entries": .array(memberNames.map { .string($0) }),
                "entries": .array(memberNames.map { ["name": .string($0), "bytes": .number(Double(byName[$0]!.count)), "digest": .string(sha(Data(byName[$0]!)))] }),
                "entry_set_digest": observations.E["digest"]]
    }
    static func firstDifference(_ actual: J, _ expected: J, _ pointer: String = "/checksums.json") -> String? {
        if actual == expected { return nil }
        guard case .object = actual, case .object = expected else { return pointer }
        var keys: [String] = []
        for key in expected.fields.keys.map({ $0.text }) + actual.fields.keys.map({ $0.text }) where !keys.contains(key) { keys.append(key) }
        for key in keys {
            if !actual.has(key) || !expected.has(key) { return pointer + "/" + key }
            if let found = firstDifference(actual[key], expected[key], pointer + "/" + key) { return found }
        }
        return nil
    }
    static func parseChecksums(_ raw: [UInt8]) throws -> J {
        if raw.count > 1048576 { try invalid() }
        let value: J
        do { value = try KDNAJSON.parse(Data(raw)) }
        catch let failure as PublicFailure where ["READ_INPUT_INVALID", "READ_CORE_INVALID"].contains(failure.code) { try invalid() }
        guard case .object = value,
              ["profile", "profile_version", "digest_profile", "digest_profile_version"].allSatisfy({ value.has($0) && !value[$0].text.isEmpty }) else {
            try invalid()
        }
        if value["profile"].text != profile || value["profile_version"].text != version
            || value["digest_profile"].text != "kdna.digest-basis.runtime-entry-set" || value["digest_profile_version"].text != "0.3.0-candidate" {
            throw PublicFailure("CHECKSUMS_PROFILE_UNSUPPORTED")
        }
        do { _ = try SectionContract.validate("ChecksumsDocument06", value) }
        catch let failure as PublicFailure where ["READ_INPUT_INVALID", "READ_CORE_INVALID", "SECTION_TYPED_SHAPE"].contains(failure.code) { try invalid() }
        return value
    }
    static func verifyChecksums(_ entries: [SectionContainer.Entry], _ observations: (A: String, C: String, E: J), _ captureId: String, _ requestDigest: String) throws -> J {
        guard let entry = entries.first(where: { $0.name == "checksums.json" }) else { return ["status": "absent"] }
        let value = try parseChecksums(entry.bytes)
        let expected = documentFor(entries, observations)
        if let field = firstDifference(value, expected) {
            let match = field.range(of: "^/checksums.json/entries/(\\d+)(/|$)", options: .regularExpression)
            var subject: String? = nil
            if let match {
                let indexText = String(field[match]).split(separator: "/")[3]
                if let index = Int(indexText) { subject = expected["entries"].list[index]["name"].text }
            }
            try invalid(field, subject)
        }
        return ["status": "verified_document_2", "profile": .string(profile), "profile_version": .string(version),
                "document_digest": .string(sha(Data(entry.bytes))), "expected_entry_set_digest": value["entry_set_digest"],
                "observed_entry_set_digest": observations.E["digest"],
                "covered_entries": observations.E["member_names"], "capture_id": .string(captureId), "request_digest": .string(requestDigest),
                "observed_A": .string(observations.A), "observed_C": .string(observations.C)]
    }
    // MARK: - Scoped (partial) verification — section-checksums.js
    // prepareScopedChecksums / completeScopedChecksums. The Node capture
    // tracks which members the flow actually read; the bytes variant carries
    // the same touched-set semantics (non-empty section reads mark members),
    // and the fd stat-key re-checks are vacuous in memory.
    static func prepareScopedChecksums(_ capture: inout SectionFaces.Capture, _ manifest: J) throws -> J? {
        guard let row = capture.row("checksums.json") else { return nil }
        if row.size > 1048576 { try invalid() }
        let raw = try capture.checksumMemberAfterAuthorization("checksums.json")
        let value = try parseChecksums(raw)
        var members: [String: Int] = [:]
        for r in capture.rows { members[r.name] = r.size }
        guard case .array(let declaredValues) = manifest["runtime"]["mandatory_entries"] else { throw PublicFailure("SECTION_RUNTIME_DECLARATION") }
        let declared = declaredValues.map { $0.text }
        try demand(Set(declared).count == declared.count, "SECTION_RUNTIME_DECLARATION")
        for name in declared {
            try demand(validEntry(name) && members[name] != nil
                && !["checksums.json", "signature.kdsig", "mimetype", "build-receipt.json"].contains(name)
                && !name.hasPrefix("reports/") && !name.hasPrefix("authoring/"), "SECTION_RUNTIME_MEMBER_MISSING")
        }
        var nameSet = Set(["kdna.json"])
        for r in capture.rows where r.name.hasPrefix("sections/") { nameSet.insert(r.name) }
        declared.forEach { nameSet.insert($0) }
        let names = nameSet.sorted(by: SectionFrameGraph.utf8Less)
        if let field = firstDifference(value["covered_entries"], .array(names.map { .string($0) }), "/checksums.json/covered_entries") { try invalid(field) }
        if value["entries"].list.count != names.count { try invalid("/checksums.json/entries") }
        for (i, name) in names.enumerated() {
            if value["entries"].list[i]["name"].text != name { try invalid("/checksums.json/entries/\(i)/name", name) }
            if value["entries"].list[i]["bytes"].numeric != Double(members[name]!) { try invalid("/checksums.json/entries/\(i)/bytes", name) }
        }
        return ["value": value, "names": .array(names.map { .string($0) }), "document_digest": .string(sha(Data(raw)))]
    }
    static func completeScopedChecksums(_ capture: inout SectionFaces.Capture, _ prepared: J?, _ requestDigest: String, _ signatureEntries: [String: [UInt8]]?) throws -> J {
        guard let prepared else {
            return ["checksum_integrity": ["status": "absent"],
                    "runtime_entry_digest": ["status": "not_checked", "profile": "kdna.digest-basis.runtime-entry-set/0.3.0-candidate", "claimed_digest": .null]]
        }
        let value = prepared["value"], names = prepared["names"].list.map { $0.text }
        let touched = Set(signatureEntries != nil ? Array(signatureEntries!.keys) : (["kdna.json"] + capture.touchedMemberNames()))
        let required = names.filter { touched.contains($0) }
        let complete = required.count == names.count
        var checkedEntries: [J] = [], uncheckedEntries: [J] = []
        for entry in value["entries"].list where !touched.contains(entry["name"].text) { uncheckedEntries.append(entry) }
        var preimage = Data()
        if complete {
            preimage += Data("KDNA-RUNTIME-ENTRY-SET\0".utf8) + Data("0.3.0-candidate\0".utf8)
            preimage += try SectionDigests.word(names.count, 4)
        }
        for name in required {
            let index = names.firstIndex(of: name)!
            let expected = value["entries"].list[index]
            let bytes: [UInt8]
            if let signatureEntries { bytes = signatureEntries[name]! }
            else if name == "kdna.json" { bytes = capture.manifestBytes }
            else { bytes = try capture.checksumMemberAfterAuthorization(name) }
            let observed = sha(Data(bytes))
            if bytes.count != Int(expected["bytes"].numeric) { try invalid("/checksums.json/entries/\(index)/bytes", name) }
            if observed != expected["digest"].text { try invalid("/checksums.json/entries/\(index)/digest", name) }
            checkedEntries.append(["name": .string(name), "bytes": .number(Double(bytes.count)), "expected_digest": expected["digest"], "observed_digest": .string(observed)])
            if complete {
                let nameBytes = Array(name.utf8)
                preimage += try SectionDigests.word(nameBytes.count, 4); preimage += Data(nameBytes)
                preimage += try SectionDigests.word(bytes.count, 8); preimage += Data(bytes)
            }
        }
        try capture.assertUnchanged()
        let entrySetDigest: J, runtimeEntryDigest: J
        if complete {
            let observed = sha(preimage)
            if observed != value["entry_set_digest"].text { try invalid("/checksums.json/entry_set_digest") }
            entrySetDigest = ["status": "verified", "expected_digest": value["entry_set_digest"], "observed_digest": .string(observed),
                              "comparison": "matched", "basis": "actual_complete_member_bytes"]
            runtimeEntryDigest = ["status": "verified", "profile": "kdna.digest-basis.runtime-entry-set/0.3.0-candidate",
                                  "digest": .string(observed), "member_names": .array(names.map { .string($0) })]
        } else {
            try demand(!uncheckedEntries.isEmpty, "SECTION_CHECKSUMS_PARTITION")
            entrySetDigest = ["status": "not_checked", "expected_digest": value["entry_set_digest"], "observed_digest": .null,
                              "comparison": "not_compared", "reason": "members_unchecked"]
            runtimeEntryDigest = ["status": "not_checked", "profile": "kdna.digest-basis.runtime-entry-set/0.3.0-candidate",
                                  "claimed_digest": value["entry_set_digest"]]
        }
        let checksumIntegrity: J = ["status": "checked_members_document_2", "profile": .string(profile), "profile_version": .string(version),
            "declaration_status": "shape_and_directory_checked", "document_digest": prepared["document_digest"],
            "covered_entries": .array(names.map { .string($0) }), "checked_entries": .array(checkedEntries), "unchecked_entries": .array(uncheckedEntries),
            "entry_set_digest": entrySetDigest, "capture_id": capture.identity["capture_id"], "request_digest": .string(requestDigest)]
        _ = try SectionContract.validate("ScopedChecksumVerification06", checksumIntegrity)
        _ = try SectionContract.validate("ScopedRuntimeEntryDigest06", runtimeEntryDigest)
        return ["checksum_integrity": checksumIntegrity, "runtime_entry_digest": runtimeEntryDigest]
    }
}
