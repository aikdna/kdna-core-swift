import Foundation

// The checksums document (section-checksums.js, @aikdna/kdna-core@0.36.0):
// the whole-read verification path — absent, or a verified
// kdna.checksums.document/2 with the first structural difference surfaced
// as SECTION_CHECKSUMS_INVALID with its field pointer and entry subject.
enum SectionChecksums {
    static let profile = "kdna.checksums.document/2", version = "2.0.0-candidate"
    static func invalid(_ field: String = "/checksums.json", _ subject: String? = nil) throws -> Never {
        throw PublicFailure("SECTION_CHECKSUMS_INVALID", field: field, subject: subject)
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
}
