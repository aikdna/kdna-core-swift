import XCTest
import CryptoKit
@testable import KDNACore

final class KDNACoreTests: XCTestCase {

    // MARK: - ZIP Helper

    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = [Data]()
        var centralParts = [Data]()
        var offset: UInt32 = 0

        func u16(_ n: UInt16) -> Data {
            var v = n
            return Data(bytes: &v, count: 2)
        }
        func u32(_ n: UInt32) -> Data {
            var v = n
            return Data(bytes: &v, count: 4)
        }

        for (name, data) in entries {
            let nameData = Data(name.utf8)
            var local = Data()
            local.append(u32(0x04034b50))
            local.append(u16(20))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u16(0))
            local.append(u32(0))
            local.append(u32(UInt32(data.count)))
            local.append(u32(UInt32(data.count)))
            local.append(u16(UInt16(nameData.count)))
            local.append(u16(0))
            local.append(nameData)
            local.append(data)
            localParts.append(local)

            var central = Data()
            central.append(u32(0x02014b50))
            central.append(u16(20))
            central.append(u16(20))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u32(0))
            central.append(u32(UInt32(data.count)))
            central.append(u32(UInt32(data.count)))
            central.append(u16(UInt16(nameData.count)))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u16(0))
            central.append(u32(0))
            central.append(u32(offset))
            central.append(nameData)
            centralParts.append(central)
            offset += UInt32(local.count)
        }

        let central = centralParts.reduce(Data(), +)
        let local = localParts.reduce(Data(), +)
        var eocd = Data()
        eocd.append(u32(0x06054b50))
        eocd.append(u16(0))
        eocd.append(u16(0))
        eocd.append(u16(UInt16(entries.count)))
        eocd.append(u16(UInt16(entries.count)))
        eocd.append(u32(UInt32(central.count)))
        eocd.append(u32(UInt32(local.count)))
        eocd.append(u16(0))
        return local + central + eocd
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func checksumRuntimeAsset(
        fields: (String) -> [String: Any]
    ) throws -> (url: URL, entrySetDigest: String) {
        let manifest = try JSONSerialization.data(withJSONObject: [
            "format_version": "0.1.0",
            "asset_id": "kdna:test:checksum-digest",
            "asset_uid": "urn:uuid:00000000-0000-4000-8000-000000000099",
            "asset_type": "fixture",
            "title": "Checksum Digest Fixture",
            "version": "1.0.0",
            "judgment_version": "1.0.0",
            "created_at": "2026-07-15T00:00:00Z",
            "updated_at": "2026-07-15T00:00:00Z",
            "compatibility": [
                "min_loader_version": "0.20.0",
                "profile": "kdna.payload.judgment",
                "profile_version": "0.1.0",
            ],
            "access": "public",
            "payload": ["path": "payload.kdnab", "encoding": "cbor", "encrypted": false]
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        let payload = try KDNACBOR.encode([
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0",
            "core": [
                "highest_question": "Which checksum field names the entry set?",
                "axioms": [
                    "Reject checksum declarations that do not bind the current runtime entry set."
                ] as [Any]
            ] as [String: Any]
        ] as [String: Any])
        let combined = [
            "kdna.json:\(sha256Hex(manifest))",
            "payload.kdnab:\(sha256Hex(payload))"
        ].joined(separator: "\n")
        let entrySetDigest = "sha256:\(sha256Hex(Data(combined.utf8)))"
        var checksums: [String: Any] = [
            "algorithm": "sha256",
            "manifest_digest": "sha256:\(sha256Hex(manifest))",
            "payload_digest": "sha256:\(sha256Hex(payload))"
        ]
        checksums.merge(fields(entrySetDigest)) { _, replacement in replacement }
        let checksumsData = try JSONSerialization.data(
            withJSONObject: checksums,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-checksum-digest-\(UUID().uuidString).kdna")
        try makeZip(entries: [
            ("mimetype", Data(KDNAAssetReader.kdnaMediaType.utf8)),
            ("kdna.json", manifest),
            ("payload.kdnab", payload),
            ("checksums.json", checksumsData)
        ]).write(to: url)
        return (url, entrySetDigest)
    }

    // MARK: - Test Fixtures

    func testAssetReaderAcceptsRuntimeContainer() throws {
        let manifestData = Data("""
        {
          "format_version": "0.1.0",
          "asset_id": "kdna:test:runtime",
          "asset_uid": "urn:uuid:00000000-0000-4000-8000-000000000001",
          "asset_type": "domain",
          "title": "Runtime",
          "version": "1.0.0",
          "judgment_version": "1.0.0",
          "created_at": "2026-07-16T00:00:00Z",
          "updated_at": "2026-07-16T00:00:00Z",
          "compatibility": {
            "min_loader_version": "0.20.0",
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0"
          },
          "access": "public",
          "payload": {
            "path": "payload.kdnab",
            "encoding": "cbor",
            "encrypted": false
          }
        }
        """.utf8)
        let payloadData = try KDNACBOR.encode([
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0",
            "core": [
                "highest_question": "Can the Swift reader accept a current Runtime container?",
                "axioms": [
                    "Accept only a container that satisfies the current Runtime contract."
                ] as [Any],
            ] as [String: Any],
        ] as [String: Any])
        let checksumsData = Data(#"{"algorithm":"sha256"}"#.utf8)
        let zipData = makeZip(entries: [
            ("mimetype", Data(KDNAAssetReader.kdnaMediaType.utf8)),
            ("kdna.json", manifestData),
            ("payload.kdnab", payloadData),
            ("checksums.json", checksumsData),
        ])

        let reader = KDNAAssetReader()
        let asset = try reader.open(data: zipData, path: "runtime.kdna")
        let result = reader.verifySync(asset)

        XCTAssertEqual(reader.mediaType(asset: asset), KDNAAssetReader.kdnaMediaType)
        XCTAssertTrue(reader.verifyMediaType(asset: asset))
        XCTAssertEqual(Set(reader.listEntries(asset: asset)), ["mimetype", "kdna.json", "payload.kdnab", "checksums.json"])
        XCTAssertTrue(result.ok, result.errors.joined(separator: "\n"))
    }

    /// Minimal valid KDNA_Core.json
    private var coreJSON: Data {
        """
        {
          "meta": {
            "version": "1.0",
            "domain": "test-writing",
            "created": "2024-01-01",
            "purpose": "Test domain",
            "load_condition": "always"
          },
          "stances": [{"stance":"Never use vague adjectives"}, {"stance":"Always start with the reader's problem"}],
          "axioms": [
            {
              "id": "axiom_1",
              "one_sentence": "Clear writing starts with the reader's problem.",
              "full_statement": "The reader must understand what problem is being solved within the first sentence.",
              "why": "Without a problem anchor, the reader has no reason to continue."
            }
          ],
          "ontology": [
            {
              "id": "concept_hook",
              "one_sentence": "A cognitive hook frames the reader's problem before the solution.",
              "essence": "Problem-first framing.",
              "boundary": "Not an emotional appeal or clickbait.",
              "trigger_signal": "how do I start"
            }
          ],
          "frameworks": [
            {
              "id": "framework_pas",
              "name": "PAS",
              "when_to_use": "When the reader has a clear pain point.",
              "steps": ["Problem", "Agitation", "Solution"]
            }
          ],
          "trigger_signals": ["writing", "draft", "review"]
        }
        """.data(using: .utf8)!
    }

    /// Minimal valid KDNA_Patterns.json
    private var patternsJSON: Data {
        """
        {
          "meta": {
            "version": "1.0",
            "domain": "test-writing",
            "created": "2024-01-01",
            "purpose": "Test domain",
            "load_condition": "always"
          },
          "terminology": {
            "standard_terms": [
              { "term": "cognitive hook", "definition": "A problem-first opening sentence." }
            ],
            "banned_terms": [
              { "term": "leverage", "why": "Vague business jargon.", "replace_with": "use" },
              { "term": "synergy", "why": "Meaningless buzzword.", "replace_with": "work together" }
            ]
          },
          "misunderstandings": [
            {
              "id": "mis_1",
              "wrong": "A hook is an emotional opening.",
              "correct": "A hook is a problem-statement opening.",
              "key_distinction": "Problem vs emotion.",
              "why": "Emotional openings manipulate; problem openings serve."
            }
          ],
          "self_check": [
            "Did I state the reader's problem in the first sentence?",
            "Did I avoid banned business jargon?"
          ]
        }
        """.data(using: .utf8)!
    }

    /// A second domain for conflict detection
    private var conflictCoreJSON: Data {
        """
        {
          "meta": {
            "version": "1.0",
            "domain": "test-security",
            "created": "2024-01-01",
            "purpose": "Security domain",
            "load_condition": "always"
          },
          "stances": [{"stance":"Always reject unverified input"}, {"stance":"Never trust client-side validation"}],
          "axioms": [
            {
              "id": "axiom_sec",
              "one_sentence": "All input is hostile until proven otherwise.",
              "full_statement": "Treat every user input as potentially malicious.",
              "why": "Security breaches start with unchecked assumptions."
            }
          ],
          "ontology": [],
          "frameworks": [],
          "trigger_signals": ["security", "input", "validate"]
        }
        """.data(using: .utf8)!
    }

    private var conflictPatternsJSON: Data {
        """
        {
          "meta": {
            "version": "1.0",
            "domain": "test-security",
            "created": "2024-01-01",
            "purpose": "Security domain",
            "load_condition": "always"
          },
          "terminology": {
            "standard_terms": [
              { "term": "leverage", "definition": "Using a vulnerability to gain access." }
            ],
            "banned_terms": [
              { "term": "trust", "why": "Security should never assume trust.", "replace_with": "verify" }
            ]
          },
          "misunderstandings": [],
          "self_check": ["Did I sanitize all inputs?"]
        }
        """.data(using: .utf8)!
    }

    // MARK: - Helpers

    private func loadTestDomain(core: Data, patterns: Data) -> KDNADomain? {
        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: core),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patterns) else {
            return nil
        }
        return KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData
        ])
    }

    private func writingDomain() -> KDNADomain {
        XCTAssertNotNil(loadTestDomain(core: coreJSON, patterns: patternsJSON))
        return loadTestDomain(core: coreJSON, patterns: patternsJSON)!
    }

    private func securityDomain() -> KDNADomain {
        XCTAssertNotNil(loadTestDomain(core: conflictCoreJSON, patterns: conflictPatternsJSON))
        return loadTestDomain(core: conflictCoreJSON, patterns: conflictPatternsJSON)!
    }

    // MARK: - Domain Loading

    func testLoadDomain() {
        let domain = writingDomain()
        XCTAssertEqual(domain.core.meta.domain, "test-writing")
        XCTAssertEqual(domain.core.axioms?.count, 1)
        XCTAssertEqual(domain.patterns.terminology?.banned_terms?.count, 2)
    }

    func testFormatContextContainsKeySections() {
        let domain = writingDomain()
        let context = KDNADomainLoader.formatContext(domain)

        XCTAssertTrue(context.contains("Domain Cognition (KDNA)"))
        XCTAssertTrue(context.contains("test-writing"))
        XCTAssertTrue(context.contains("Stances"))
        XCTAssertTrue(context.contains("Axioms"))
        XCTAssertTrue(context.contains("Avoid These Terms"))
        XCTAssertTrue(context.contains("Watch For These Misunderstandings"))
        XCTAssertTrue(context.contains("Before Responding, Check"))
    }

    func testFormatContextBannedTerms() {
        let domain = writingDomain()
        let context = KDNADomainLoader.formatContext(domain)

        XCTAssertTrue(context.contains("leverage"))
        XCTAssertTrue(context.contains("synergy"))
        XCTAssertTrue(context.contains("use"))
    }

    // MARK: - Pre-Filter

    func testPreFilterDetectsBannedTerm() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "We should leverage our synergy.", domains: [domain])

        XCTAssertFalse(result.shouldBlock)
        XCTAssertEqual(result.bannedTerms.count, 2)
        XCTAssertTrue(result.bannedTerms.contains { $0.term == "leverage" })
        XCTAssertTrue(result.bannedTerms.contains { $0.term == "synergy" })
    }

    func testPreFilterReportsBannedTermsWithoutBlocking() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "Let's leverage this.", domains: [domain])

        XCTAssertFalse(result.shouldBlock)
        XCTAssertNil(result.blockReason)
        XCTAssertEqual(result.bannedTerms.count, 1)
        XCTAssertEqual(result.bannedTerms.first?.term, "leverage")
    }

    func testPreFilterWithoutBannedTermsDoesNothing() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "Let's improve this.", domains: [domain])

        XCTAssertFalse(result.shouldBlock)
        XCTAssertTrue(result.bannedTerms.isEmpty)
    }

    func testPreFilterSignalDetection() {
        // Add scenarios to the domain for signal detection
        let scenariosJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Draft Review", "trigger_signals": ["review my draft"] }
          ]
        }
        """.data(using: .utf8)!
        guard let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON) else {
            XCTFail("Failed to decode scenarios")
            return
        }
        var domain = writingDomain()
        domain.scenarios = scenariosData

        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "Can you review my draft?", domains: [domain])

        XCTAssertFalse(result.signals.isEmpty)
        XCTAssertTrue(result.signals.contains { $0.contains("Draft Review") })
    }

    // MARK: - Post-Validate

    func testPostValidateDetectsBannedTermInResponse() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.postValidate(response: "You should leverage this feature.", domains: [domain])

        XCTAssertFalse(result.passed)
        XCTAssertEqual(result.bannedTerms.count, 1)
        XCTAssertEqual(result.bannedTerms.first?.term, "leverage")
    }

    func testPostValidateDetectsMisunderstanding() {
        let domain = writingDomain()
        XCTAssertNotNil(domain.patterns.misunderstandings)
        let wrong = domain.patterns.misunderstandings!.first!.wrong
        // Note: wrong text includes a period, so response must contain the exact text
        let response = "A common mistake: \(wrong) This is incorrect because..."

        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.postValidate(
            response: response,
            domains: [domain]
        )

        XCTAssertFalse(result.misunderstandings.isEmpty)
        XCTAssertTrue(result.misunderstandings.contains { $0.contains(wrong) })
    }

    func testPostValidateWithBannedTermsFails() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.postValidate(response: "Bad response with leverage and synergy.", domains: [domain])

        XCTAssertFalse(result.passed)
        XCTAssertEqual(result.bannedTerms.count, 2)
    }

    // MARK: - Multi-Domain Composition

    func testComposeContextJoinsDomains() {
        let d1 = writingDomain()
        let d2 = securityDomain()
        let composed = KDNACompose.composeContext(domains: [d1, d2])

        XCTAssertTrue(composed.contains("test-writing"))
        XCTAssertTrue(composed.contains("test-security"))
        XCTAssertTrue(composed.contains("---"))
    }

    func testClassifySignalsMatchesDomain() {
        let d1 = writingDomain()
        let d2 = securityDomain()
        let matched = KDNACompose.classifySignals(input: "I need help with my writing draft.", domains: [d1, d2])

        XCTAssertTrue(matched.contains("test-writing"))
    }

    func testDetectConflictsFindsBannedVsStandard() {
        let d1 = writingDomain()   // bans "leverage"
        let d2 = securityDomain()  // uses "leverage" as standard term
        let conflicts = KDNACompose.detectConflicts(domains: [d1, d2])

        XCTAssertFalse(conflicts.isEmpty)
        XCTAssertTrue(conflicts.contains { $0.contains("leverage") })
    }

    func testDetectConflictsFindsStanceConflict() {
        let d1 = writingDomain()   // stance: "Always start with the reader's problem"
        // Create a domain with opposite stance
        let oppositeCoreJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-opposite", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"Never start with the reader's problem"}],
          "axioms": [], "ontology": [], "frameworks": []
        }
        """.data(using: .utf8)!
        let oppositePatternsJSON = """
        { "meta": { "version": "1.0", "domain": "test-opposite", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "terminology": { "banned_terms": [], "standard_terms": [] }, "misunderstandings": [], "self_check": [] }
        """.data(using: .utf8)!

        guard let d2 = loadTestDomain(core: oppositeCoreJSON, patterns: oppositePatternsJSON) else {
            XCTFail("Failed to load opposite domain")
            return
        }

        let conflicts = KDNACompose.detectConflicts(domains: [d1, d2])
        XCTAssertFalse(conflicts.isEmpty)
    }

    func testDetectConflictsEmptyForSingleDomain() {
        let d1 = writingDomain()
        let conflicts = KDNACompose.detectConflicts(domains: [d1])
        XCTAssertTrue(conflicts.isEmpty)
    }

    // MARK: - Validation

    func testLintDomain() {
        let domain = writingDomain()
        let (errors, _) = KDNADomainValidator.lintDomain(domain)
        XCTAssertTrue(errors.isEmpty)
        // The test domain has all required fields, so no errors expected
    }

    func testLintDomainMissingAxioms() {
        let badCoreJSON = """
        {
          "meta": { "version": "1.0", "domain": "bad", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"S1"}], "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: badCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON) else {
            XCTFail("Decode failed")
            return
        }
        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let (errors, _) = KDNADomainValidator.lintDomain(domain)
        XCTAssertFalse(errors.isEmpty)
        XCTAssertTrue(errors.contains { $0.contains("axioms") })
    }

    func testValidateDomainDirectory() {
        // Create a temporary directory with required files
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("kdna_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        // Missing required files → invalid
        let resultEmpty = KDNADomainLoader.validate(path: tempDir.path)
        XCTAssertFalse(resultEmpty.valid)

        // Add required files → valid
        try? coreJSON.write(to: tempDir.appendingPathComponent("KDNA_Core.json"))
        try? patternsJSON.write(to: tempDir.appendingPathComponent("KDNA_Patterns.json"))
        let resultValid = KDNADomainLoader.validate(path: tempDir.path)
        XCTAssertTrue(resultValid.valid)
        XCTAssertEqual(resultValid.fileCount, 2)
    }

    func testLoadManifest() {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("kdna_manifest_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        let manifestJSON = """
        {
          "format_version": "0.1.0",
          "asset_id": "kdna:test:domain",
          "asset_uid": "urn:uuid:00000000-0000-4000-8000-000000000011",
          "asset_type": "fixture",
          "title": "Test domain",
          "version": "0.1.0",
          "judgment_version": "0.1.0",
          "created_at": "2026-07-15T00:00:00Z",
          "updated_at": "2026-07-15T00:00:00Z",
          "compatibility": {
            "min_loader_version": "0.20.0",
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0"
          },
          "payload": {"path": "payload.kdnab", "encoding": "cbor", "encrypted": false},
          "status": "experimental"
        }
        """.data(using: .utf8)!
        try? manifestJSON.write(to: tempDir.appendingPathComponent("kdna.json"))

        let manifest = KDNADomainLoader.loadManifest(from: tempDir.path)
        XCTAssertNotNil(manifest)
        XCTAssertEqual(manifest?.asset_id, "kdna:test:domain")
        XCTAssertEqual(manifest?.compatibility.profile_version, "0.1.0")
    }

    // MARK: - Build System Message

    func testBuildSystemMessageWithDomain() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(domain: domain, baseSystemMessage: "Be helpful.", projectContext: nil)

        XCTAssertTrue(msg.contains("KDNA DOMAIN COGNITION"))
        XCTAssertTrue(msg.contains("BASE INSTRUCTIONS"))
        XCTAssertTrue(msg.contains("Be helpful."))
    }

    func testBuildSystemMessageWithoutDomain() {
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(domain: nil, baseSystemMessage: "Be helpful.", projectContext: nil)

        XCTAssertTrue(msg.contains("Be helpful."))
        XCTAssertFalse(msg.contains("KDNA DOMAIN COGNITION"))
    }

    func testBuildSystemMessageMultiDomain() {
        let d1 = writingDomain()
        let d2 = securityDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(domains: [d1, d2], baseSystemMessage: "Be helpful.", projectContext: "Project X")

        XCTAssertTrue(msg.contains("KDNA DOMAIN COGNITION"))
        XCTAssertTrue(msg.contains("test-writing"))
        XCTAssertTrue(msg.contains("test-security"))
        XCTAssertTrue(msg.contains("PROJECT CONTEXT"))
        XCTAssertTrue(msg.contains("Project X"))
    }

    func testBuildSystemMessagePersonaFirstStrategy() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(
            domain: domain,
            baseSystemMessage: "Be helpful.",
            projectContext: nil,
            strategy: .personaFirst
        )

        XCTAssertTrue(msg.contains("KDNA DOMAIN COGNITION"))
        XCTAssertTrue(msg.contains("BASE INSTRUCTIONS"))
        let baseRange = msg.range(of: "BASE INSTRUCTIONS")!
        let kdnaRange = msg.range(of: "KDNA DOMAIN COGNITION")!
        XCTAssertLessThan(baseRange.lowerBound, kdnaRange.lowerBound)
    }

    func testBuildSystemMessageCompactDomainStrategy() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(
            domain: domain,
            baseSystemMessage: "Be helpful.",
            projectContext: nil,
            strategy: .compactDomain
        )

        XCTAssertTrue(msg.contains("Domain: test-writing"))
        XCTAssertTrue(msg.contains("Axioms:"))
        XCTAssertTrue(msg.contains("Self-Checks:"))
        XCTAssertFalse(msg.contains("Key Concepts"))
    }

    func testBuildSystemMessageStrictJudgmentStrategy() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(
            domain: domain,
            baseSystemMessage: "Be helpful.",
            projectContext: nil,
            strategy: .strictJudgment
        )

        XCTAssertTrue(msg.contains("STRICT"))
        XCTAssertTrue(msg.contains("CLASSIFY"))
        XCTAssertTrue(msg.contains("VERIFY"))
    }

    // MARK: - Domain Loading from Filesystem

    func testLoadDomainFromPath() {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("kdna_path_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        try? coreJSON.write(to: tempDir.appendingPathComponent("KDNA_Core.json"))
        try? patternsJSON.write(to: tempDir.appendingPathComponent("KDNA_Patterns.json"))

        let domain = KDNADomainLoader.load(path: tempDir.path)
        XCTAssertNotNil(domain)
        XCTAssertEqual(domain?.core.meta.domain, "test-writing")
    }

    func testLoadDomainFromPathMissingRequired() {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("kdna_missing_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        // Only write core, missing patterns
        try? coreJSON.write(to: tempDir.appendingPathComponent("KDNA_Core.json"))

        let domain = KDNADomainLoader.load(path: tempDir.path)
        XCTAssertNil(domain)
    }

    func testLoadDomainFromPathWithOptionalFiles() {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("kdna_opt_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        try? coreJSON.write(to: tempDir.appendingPathComponent("KDNA_Core.json"))
        try? patternsJSON.write(to: tempDir.appendingPathComponent("KDNA_Patterns.json"))

        let scenariosJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "scenes": [] }
        """.data(using: .utf8)!
        try? scenariosJSON.write(to: tempDir.appendingPathComponent("KDNA_Scenarios.json"))

        let domain = KDNADomainLoader.load(path: tempDir.path, mode: "all")
        XCTAssertNotNil(domain)
        XCTAssertNotNil(domain?.scenarios)
    }

    // MARK: - loadDomain Modes

    func testLoadDomainMinimumMode() {
        let scenariosJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "scenes": [] }
        """.data(using: .utf8)!
        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData
        ], mode: "minimum")

        XCTAssertNotNil(domain)
        XCTAssertNil(domain?.scenarios)
    }

    func testLoadDomainAllMode() {
        let scenariosJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "scenes": [] }
        """.data(using: .utf8)!
        let casesJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "cases": [] }
        """.data(using: .utf8)!
        let reasoningJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "reasoning_chains": [] }
        """.data(using: .utf8)!
        let evolutionJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "stages": [] }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON),
              let reasoningData = try? JSONDecoder().decode(KDNAReasoningData.self, from: reasoningJSON),
              let evolutionData = try? JSONDecoder().decode(KDNAEvolutionData.self, from: evolutionJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData,
            "cases": casesData,
            "reasoning": reasoningData,
            "evolution": evolutionData
        ], mode: "all")

        XCTAssertNotNil(domain)
        XCTAssertNotNil(domain?.scenarios)
        XCTAssertNotNil(domain?.cases)
        XCTAssertNotNil(domain?.reasoning)
        XCTAssertNotNil(domain?.evolution)
    }

    func testLoadDomainAutoModeClassifiesInput() {
        let scenariosJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "scenes": [] }
        """.data(using: .utf8)!
        let reasoningJSON = """
        { "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "reasoning_chains": [] }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let reasoningData = try? JSONDecoder().decode(KDNAReasoningData.self, from: reasoningJSON) else {
            XCTFail("Decode failed")
            return
        }

        // Input with scenario keyword should load scenarios
        let domainWithScenarios = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData,
            "reasoning": reasoningData
        ], input: "What is the situation?", mode: "auto")

        XCTAssertNotNil(domainWithScenarios?.scenarios)
        XCTAssertNil(domainWithScenarios?.cases)

        // Input with reasoning keyword should load reasoning
        let domainWithReasoning = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData,
            "reasoning": reasoningData
        ], input: "Why does this matter?", mode: "auto")

        XCTAssertNotNil(domainWithReasoning?.reasoning)
        XCTAssertNil(domainWithReasoning?.cases)

        // Input with no keywords should load nothing optional
        let domainMinimal = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData,
            "reasoning": reasoningData
        ], input: "Hello world", mode: "auto")

        XCTAssertNil(domainMinimal?.scenarios)
        XCTAssertNil(domainMinimal?.reasoning)
    }

    // MARK: - Format Context with Optional Files

    func testFormatContextWithAllOptionalFiles() {
        let scenariosJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Draft Review", "trigger_signals": ["review my draft"] }
          ]
        }
        """.data(using: .utf8)!
        let reasoningJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "reasoning_chains": [
            { "id": "rc_1", "one_sentence": "Start with the problem.", "logic": "Problem-first framing creates engagement.", "so_what": "Hooks the reader immediately." }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1",
              "title": "Bad Opening",
              "context": "Blog post",
              "what_happened": "Started with fluff.",
              "what_was_learned": "Start with problem.",
              "structural_pattern": "Problem-first"
            }
          ]
        }
        """.data(using: .utf8)!
        let evolutionJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-writing", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stages": [
            { "id": "s1", "name": "Beginner", "description": "Uses clichés." }
          ],
          "evolution_layers": [
            { "id": "l1", "name": "Clarity", "capability": "Clear sentences", "from_stage": "Beginner", "to_stage": "Intermediate" }
          ],
          "measurement": [
            { "id": "m1", "what": "Readability", "how": "Flesch score", "threshold": "60+" }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let reasoningData = try? JSONDecoder().decode(KDNAReasoningData.self, from: reasoningJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON),
              let evolutionData = try? JSONDecoder().decode(KDNAEvolutionData.self, from: evolutionJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomainLoader.loadDomain(dataMap: [
            "core": coreData,
            "patterns": patternsData,
            "scenarios": scenariosData,
            "cases": casesData,
            "reasoning": reasoningData,
            "evolution": evolutionData
        ], mode: "all")!

        let context = KDNADomainLoader.formatContext(domain)

        XCTAssertTrue(context.contains("Relevant Scenarios"))
        XCTAssertTrue(context.contains("Draft Review"))
        XCTAssertTrue(context.contains("Reasoning Chains"))
        XCTAssertTrue(context.contains("Start with the problem."))
        XCTAssertTrue(context.contains("Cases"))
        XCTAssertTrue(context.contains("Bad Opening"))
        XCTAssertTrue(context.contains("Growth Stages"))
        XCTAssertTrue(context.contains("Beginner"))
        XCTAssertTrue(context.contains("Capability Layers"))
        XCTAssertTrue(context.contains("Clarity"))
        XCTAssertTrue(context.contains("Measurement"))
        XCTAssertTrue(context.contains("Flesch score"))
    }

    // MARK: - Pre-Filter Edge Cases

    func testPreFilterEmptyDomains() {
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "Hello world", domains: [])

        XCTAssertFalse(result.shouldBlock)
        XCTAssertTrue(result.bannedTerms.isEmpty)
        XCTAssertTrue(result.signals.isEmpty)
    }

    func testPreFilterEnforceNoBannedTerms() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.preFilter(input: "Hello world, no banned words here.", domains: [domain])

        XCTAssertFalse(result.shouldBlock)
        XCTAssertTrue(result.bannedTerms.isEmpty)
    }

    // MARK: - Post-Validate Edge Cases

    func testPostValidateSelfChecksFailed() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        // Response that does not address any self-check keywords (avoid substrings)
        let result = pipeline.postValidate(
            response: "foo bar baz quux",
            domains: [domain]
        )

        XCTAssertFalse(result.selfChecksFailed.isEmpty)
        XCTAssertTrue(result.selfChecksFailed.contains { $0.contains("reader's problem") })
    }

    func testPostValidateSelfChecksPassed() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        // Response that addresses both self-checks
        let result = pipeline.postValidate(
            response: "The reader's problem is stated in the first sentence. We avoid banned business jargon.",
            domains: [domain]
        )

        XCTAssertTrue(result.selfChecksFailed.isEmpty)
    }

    func testPostValidateEmptyDomains() {
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.postValidate(response: "Any response.", domains: [])

        XCTAssertTrue(result.passed)
        XCTAssertTrue(result.bannedTerms.isEmpty)
    }

    func testPostValidateMultiDomain() {
        let d1 = writingDomain()
        let d2 = securityDomain()
        let pipeline = KDNJudgmentPipeline()
        let result = pipeline.postValidate(
            response: "You should leverage this feature and trust the client.",
            domains: [d1, d2]
        )

        XCTAssertFalse(result.passed)
        XCTAssertEqual(result.bannedTerms.count, 2)
        XCTAssertTrue(result.bannedTerms.contains { $0.term == "leverage" })
        XCTAssertTrue(result.bannedTerms.contains { $0.term == "trust" })
    }

    // MARK: - Build System Message Edge Cases

    func testBuildSystemMessageWithProjectContext() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(domain: domain, baseSystemMessage: "Be helpful.", projectContext: "This is project alpha.")

        XCTAssertTrue(msg.contains("PROJECT CONTEXT"))
        XCTAssertTrue(msg.contains("This is project alpha."))
    }

    // MARK: - KDNACompose Edge Cases

    func testComposeChecksSingleDomain() {
        let d1 = writingDomain()
        let checks = KDNACompose.composeChecks(domains: [d1])

        XCTAssertEqual(checks.count, 2)
        XCTAssertTrue(checks.contains { $0.contains("reader's problem") })
    }

    func testComposeChecksMultipleDomains() {
        let d1 = writingDomain()
        let d2 = securityDomain()
        let checks = KDNACompose.composeChecks(domains: [d1, d2])

        XCTAssertTrue(checks.contains { $0.hasPrefix("[test-writing]") })
        XCTAssertTrue(checks.contains { $0.hasPrefix("[test-security]") })
    }

    func testComposeContextEmptyDomains() {
        let composed = KDNACompose.composeContext(domains: [])
        XCTAssertTrue(composed.isEmpty)
    }

    func testClassifySignalsNoMatch() {
        let d1 = writingDomain()
        let matched = KDNACompose.classifySignals(input: "xyz random unrelated text", domains: [d1])
        // writingDomain has trigger_signals, so no match means empty
        XCTAssertTrue(matched.isEmpty)
    }

    func testClassifySignalsEmptyTriggerSignalsMatchesAll() {
        let coreNoSignals = """
        {
          "meta": { "version": "1.0", "domain": "no-signals", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"S1"}], "axioms": [], "ontology": [], "frameworks": []
        }
        """.data(using: .utf8)!
        let patternsMinimal = """
        { "meta": { "version": "1.0", "domain": "no-signals", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "terminology": { "banned_terms": [], "standard_terms": [] }, "misunderstandings": [], "self_check": [] }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreNoSignals),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsMinimal) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let matched = KDNACompose.classifySignals(input: "anything", domains: [domain])
        XCTAssertTrue(matched.contains("no-signals"))
    }

    func testDetectConflictsNoConflict() {
        let d1 = writingDomain()
        // Create a second domain with stances that do not conflict
        let noConflictCoreJSON = """
        {
          "meta": { "version": "1.0", "domain": "test-noconflict", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"Be clear and concise"}],
          "axioms": [], "ontology": [], "frameworks": []
        }
        """.data(using: .utf8)!
        let noConflictPatternsJSON = """
        { "meta": { "version": "1.0", "domain": "test-noconflict", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "terminology": { "banned_terms": [], "standard_terms": [] }, "misunderstandings": [], "self_check": [] }
        """.data(using: .utf8)!

        guard let d3 = loadTestDomain(core: noConflictCoreJSON, patterns: noConflictPatternsJSON) else {
            XCTFail("Failed to load no-conflict domain")
            return
        }

        let conflicts = KDNACompose.detectConflicts(domains: [d1, d3])
        XCTAssertTrue(conflicts.isEmpty)
    }

    // MARK: - Domain Validator Edge Cases

    func testLintDomainMissingOntology() {
        let badCoreJSON = """
        {
          "meta": { "version": "1.0", "domain": "bad", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"S1"}], "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: badCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON) else {
            XCTFail("Decode failed")
            return
        }
        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let (errors, _) = KDNADomainValidator.lintDomain(domain)
        XCTAssertTrue(errors.contains { $0.contains("ontology") })
    }

    func testLintDomainVaguePhrases() {
        let vagueCoreJSON = """
        {
          "meta": { "version": "1.0", "domain": "vague", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "stances": [{"stance":"S1"}],
          "axioms": [
            { "id": "a1", "one_sentence": "We should be helpful and achieve excellence.", "full_statement": "Best practices require user-centric innovation.", "why": "Because." }
          ],
          "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        let minimalPatterns = """
        { "meta": { "version": "1.0", "domain": "vague", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" }, "terminology": { "banned_terms": [], "standard_terms": [] }, "misunderstandings": [], "self_check": [] }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: vagueCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: minimalPatterns) else {
            XCTFail("Decode failed")
            return
        }
        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let (_, warnings) = KDNADomainValidator.lintDomain(domain)
        XCTAssertTrue(warnings.contains { $0.contains("be helpful") || $0.contains("excellence") || $0.contains("best practices") || $0.contains("user-centric") || $0.contains("innovation") })
    }

    func testValidateCrossFile() {
        let scenariosJSON = """
        {
          "meta": { "version": "1.0", "domain": "test", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Scene One", "trigger_signals": ["test"] }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "1.0", "domain": "test", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1", "title": "Case One", "context": "C", "what_happened": "W",
              "what_was_learned": "L", "structural_pattern": "P", "scene_id": "scene_1"
            }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(
            core: coreData, patterns: patternsData,
            scenarios: scenariosData, cases: casesData,
            reasoning: nil, evolution: nil
        )
        let (errors, _) = KDNADomainValidator.validateCrossFile(domain)
        XCTAssertTrue(errors.isEmpty)
    }

    func testValidateCrossFileMissingScene() {
        let casesJSON = """
        {
          "meta": { "version": "1.0", "domain": "test", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1", "title": "Case One", "context": "C", "what_happened": "W",
              "what_was_learned": "L", "structural_pattern": "P", "scene_id": "missing_scene"
            }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(
            core: coreData, patterns: patternsData,
            scenarios: nil, cases: casesData,
            reasoning: nil, evolution: nil
        )
        let (errors, _) = KDNADomainValidator.validateCrossFile(domain)
        // No scenarios at all → no cross-file check possible; should not error
        XCTAssertTrue(errors.isEmpty)
    }

    func testValidateCrossFileMissingSceneWithScenes() {
        let scenariosJSON = """
        {
          "meta": { "version": "1.0", "domain": "test", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Scene One", "trigger_signals": ["test"] }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "1.0", "domain": "test", "created": "2024-01-01", "purpose": "Test", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1", "title": "Case One", "context": "C", "what_happened": "W",
              "what_was_learned": "L", "structural_pattern": "P", "scene_id": "missing_scene"
            }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(
            core: coreData, patterns: patternsData,
            scenarios: scenariosData, cases: casesData,
            reasoning: nil, evolution: nil
        )
        let (errors, _) = KDNADomainValidator.validateCrossFile(domain)
        XCTAssertFalse(errors.isEmpty)
        XCTAssertTrue(errors.contains { $0.contains("missing_scene") })
    }

    // MARK: - Scan Domains

    func testScanDomains() {
        let fm = FileManager.default
        let baseDir = fm.temporaryDirectory.appendingPathComponent("kdna_scan_test_\(UUID().uuidString)")
        try? fm.createDirectory(at: baseDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: baseDir) }

        // Create two domain subdirectories
        let domainA = baseDir.appendingPathComponent("domain-a")
        let domainB = baseDir.appendingPathComponent("domain-b")
        try? fm.createDirectory(at: domainA, withIntermediateDirectories: true)
        try? fm.createDirectory(at: domainB, withIntermediateDirectories: true)

        try? coreJSON.write(to: domainA.appendingPathComponent("KDNA_Core.json"))
        try? patternsJSON.write(to: domainA.appendingPathComponent("KDNA_Patterns.json"))
        try? coreJSON.write(to: domainB.appendingPathComponent("KDNA_Core.json"))
        try? patternsJSON.write(to: domainB.appendingPathComponent("KDNA_Patterns.json"))

        let domains = KDNADomainLoader.scanDomains(at: baseDir.path)
        XCTAssertEqual(domains.count, 2)
        XCTAssertNotNil(domains["domain-a"])
        XCTAssertNotNil(domains["domain-b"])
    }

    func testScanDomainsEmptyDirectory() {
        let fm = FileManager.default
        let baseDir = fm.temporaryDirectory.appendingPathComponent("kdna_scan_empty_\(UUID().uuidString)")
        try? fm.createDirectory(at: baseDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: baseDir) }

        let domains = KDNADomainLoader.scanDomains(at: baseDir.path)
        XCTAssertTrue(domains.isEmpty)
    }

    func testScanDomainsNonexistentPath() {
        let domains = KDNADomainLoader.scanDomains(at: "/nonexistent/path/for/kdna")
        XCTAssertTrue(domains.isEmpty)
    }

    // MARK: - Judgment governance Schema Upgrades

    func testJudgmentGovernanceNewFieldsParsing() {
        let governanceCoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "governance-test", "created": "2026-05-22", "purpose": "Test Judgment governance", "load_condition": "always" },
          "highest_question": "What is the structural problem, not the language problem?",
          "worldview": ["Readers are busy and skeptical", "Smooth prose can hide empty thinking"],
          "judgment_role": { "acts_as": "structural diagnostician", "does_not_act_as": "language editor or cheerleader", "responsibility": "Identify the root cause before suggesting fixes" },
          "value_order": ["structural clarity > language polish", "specific evidence > abstract explanation"],
          "stances": [{"stance":"S1"}],
          "axioms": [
            {
              "id": "ax_1",
              "one_sentence": "Test axiom.",
              "full_statement": "Full test.",
              "why": "Why test.",
              "applies_when": ["user asks for feedback"],
              "does_not_apply_when": ["user asks for grammar only"],
              "failure_risk": "Misidentifying structural issues as language issues.",
              "confidence": "high",
              "evidence_type": ["practice_pattern"]
            }
          ],
          "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        let governancePatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "governance-test", "created": "2026-05-22", "purpose": "Test Judgment governance", "load_condition": "always" },
          "terminology": { "banned_terms": [], "standard_terms": [] },
          "misunderstandings": [],
          "self_check": ["Check 1"],
          "aesthetic_preferences": [
            { "prefer": "specific evidence", "avoid": "abstract claims", "signals_good": ["named examples", "exact numbers"], "signals_bad": ["vague qualifiers"] }
          ],
          "boundaries": [
            { "rule": "Never suggest language polish without structural diagnosis first.", "why": "Surface fixes mask root problems.", "must_not_do": "Suggest 'make it more engaging' without naming the structural failure.", "acceptable_exception": "User explicitly asks for proofreading only." }
          ],
          "risk_model": {
            "highest_risk_errors": ["Treating language polish as a solution to structural voids"],
            "acceptable_errors": ["Minor formatting suggestions after structural diagnosis"],
            "must_block_when": "The user asks for 'polish' and the agent has not diagnosed structure.",
            "warn_when": "The agent suggests formatting before identifying the core claim."
          },
          "counterexamples": [
            { "bad_example": "'Make it more engaging' without naming the engagement failure.", "why_bad": "Non-diagnosis that wastes the user's time.", "violated_axioms": ["ax_1"], "better_direction": "Name the specific structural failure first." }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: governanceCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: governancePatternsJSON) else {
            XCTFail("Judgment governance decode failed")
            return
        }

        XCTAssertEqual(coreData.highest_question, "What is the structural problem, not the language problem?")
        XCTAssertEqual(coreData.worldview?.count, 2)
        XCTAssertEqual(coreData.judgment_role?.acts_as, "structural diagnostician")
        XCTAssertEqual(coreData.value_order?.count, 2)

        let axiom = coreData.axioms?.first
        XCTAssertEqual(axiom?.applies_when?.count, 1)
        XCTAssertEqual(axiom?.does_not_apply_when?.count, 1)
        XCTAssertEqual(axiom?.failure_risk, "Misidentifying structural issues as language issues.")
        XCTAssertEqual(axiom?.confidence, "high")

        XCTAssertEqual(patternsData.aesthetic_preferences?.count, 1)
        XCTAssertEqual(patternsData.boundaries?.count, 1)
        XCTAssertEqual(patternsData.risk_model?.highest_risk_errors?.count, 1)
        XCTAssertEqual(patternsData.counterexamples?.count, 1)
    }

    func testJudgmentGovernanceNewFieldsFormatContext() {
        let governanceCoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "governance-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "highest_question": "What is the structural problem?",
          "worldview": ["Readers are busy"],
          "judgment_role": { "acts_as": "diagnostician", "does_not_act_as": "editor", "responsibility": "Find root cause" },
          "value_order": ["clarity > polish"],
          "stances": [{"stance":"S1"}],
          "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
          "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        let governancePatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "governance-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "terminology": { "banned_terms": [], "standard_terms": [] },
          "misunderstandings": [],
          "self_check": [],
          "aesthetic_preferences": [{ "prefer": "specific", "avoid": "vague", "signals_good": ["named"], "signals_bad": ["maybe"] }],
          "boundaries": [{ "rule": "No polish first.", "why": "Masks root.", "must_not_do": "Suggest polish.", "acceptable_exception": "Proofreading only." }],
          "risk_model": { "highest_risk_errors": ["Polish over structure"], "must_block_when": "Polish without diagnosis." },
          "counterexamples": [{ "bad_example": "Bad.", "why_bad": "Wrong.", "violated_axioms": ["a"], "better_direction": "Better." }]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: governanceCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: governancePatternsJSON) else {
            XCTFail("Decode failed")
            return
        }
        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let context = KDNADomainLoader.formatContext(domain)

        XCTAssertTrue(context.contains("Highest Question"))
        XCTAssertTrue(context.contains("What is the structural problem?"))
        XCTAssertTrue(context.contains("Worldview"))
        XCTAssertTrue(context.contains("Readers are busy"))
        XCTAssertTrue(context.contains("Judgment Role"))
        XCTAssertTrue(context.contains("Acts as: diagnostician"))
        XCTAssertTrue(context.contains("Value Order"))
        XCTAssertTrue(context.contains("clarity > polish"))
        XCTAssertTrue(context.contains("Aesthetic Preferences"))
        XCTAssertTrue(context.contains("Boundaries"))
        XCTAssertTrue(context.contains("Risk Model"))
        XCTAssertTrue(context.contains("Counterexamples"))
    }

    func testJudgmentGovernanceLintMissingGovernanceFields() {
        // Domain without optional governance fields should produce warnings but no errors
        let domain = writingDomain()
        let (_, warnings) = KDNADomainValidator.lintDomain(domain)
        XCTAssertTrue(warnings.contains { $0.contains("applies_when") })
        XCTAssertTrue(warnings.contains { $0.contains("does_not_apply_when") })
        XCTAssertTrue(warnings.contains { $0.contains("highest_question") })
        XCTAssertTrue(warnings.contains { $0.contains("worldview") })
        XCTAssertTrue(warnings.contains { $0.contains("judgment_role") })
        XCTAssertTrue(warnings.contains { $0.contains("value_order") })
        XCTAssertTrue(warnings.contains { $0.contains("aesthetic_preferences") })
        XCTAssertTrue(warnings.contains { $0.contains("risk_model") })
        XCTAssertTrue(warnings.contains { $0.contains("counterexamples") })
    }

    func testJudgmentGovernanceBuildSystemMessageStrictJudgment() {
        let domain = writingDomain()
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(
            domain: domain,
            baseSystemMessage: "Be helpful.",
            projectContext: nil,
            strategy: .strictJudgment
        )
        XCTAssertTrue(msg.contains("RESPECT the value order"))
        XCTAssertTrue(msg.contains("HONOR boundaries"))
        XCTAssertTrue(msg.contains("EVALUATE risk"))
    }

    func testJudgmentGovernanceCompactDomainIncludesNewFields() {
        let governanceCoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "compact-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "highest_question": "HQ?",
          "worldview": ["W1"],
          "value_order": ["Safety first"],
          "stances": [{"stance":"S1"}],
          "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
          "ontology": [], "frameworks": []
        }
        """.data(using: .utf8)!
        let governancePatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "compact-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "terminology": { "banned_terms": [], "standard_terms": [] },
          "misunderstandings": [],
          "self_check": ["Check 1"],
          "risk_model": { "highest_risk_errors": ["R1"] }
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: governanceCoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: governancePatternsJSON) else {
            XCTFail("Decode failed")
            return
        }
        let domain = KDNADomain(core: coreData, patterns: patternsData)
        let pipeline = KDNJudgmentPipeline()
        let msg = pipeline.buildSystemMessage(
            domain: domain,
            baseSystemMessage: "Be helpful.",
            projectContext: nil,
            strategy: .compactDomain
        )
        XCTAssertTrue(msg.contains("Q: HQ?"))
        XCTAssertTrue(msg.contains("Worldview: W1"))
        XCTAssertTrue(msg.contains("Values: Safety first"))
        XCTAssertTrue(msg.contains("Risk: R1"))
    }

    func testOptionalJudgmentGovernanceFields() {
        // Ensure domains without optional governance fields still load and format correctly
        let domain = writingDomain()
        XCTAssertNil(domain.core.highest_question)
        XCTAssertNil(domain.core.worldview)
        XCTAssertNil(domain.core.judgment_role)
        XCTAssertNil(domain.core.value_order)
        XCTAssertNil(domain.patterns.aesthetic_preferences)
        XCTAssertNil(domain.patterns.boundaries)
        XCTAssertNil(domain.patterns.risk_model)
        XCTAssertNil(domain.patterns.counterexamples)

        let context = KDNADomainLoader.formatContext(domain)
        XCTAssertFalse(context.contains("Highest Question"))
        XCTAssertFalse(context.contains("Worldview"))
        // Required base fields remain present
        XCTAssertTrue(context.contains("Stances"))
        XCTAssertTrue(context.contains("Axioms"))
    }

    // MARK: - Scenario governance Schema Upgrades

    func testScenarioGovernanceScenarioNewFieldsParsing() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-test", "created": "2026-05-22", "purpose": "Test Scenario governance", "load_condition": "always" },
          "scenes": [
            {
              "id": "scene_1",
              "name": "Test Scene",
              "trigger_signals": ["signal one", "signal two"],
              "negative_signals": ["not this", "not that"],
              "classification_rule": "If X then Y",
              "risk_level": "high",
              "expected_judgment_shift": "From A to B"
            }
          ]
        }
        """.data(using: .utf8)!

        guard let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON) else {
            XCTFail("Scenario governance scenario decode failed")
            return
        }

        let scene = scenariosData.scenes?.first
        XCTAssertEqual(scene?.trigger_signals?.count, 2)
        XCTAssertEqual(scene?.negative_signals?.count, 2)
        XCTAssertEqual(scene?.classification_rule, "If X then Y")
        XCTAssertEqual(scene?.risk_level, "high")
        XCTAssertEqual(scene?.expected_judgment_shift, "From A to B")
    }

    func testScenarioRejectsRemovedSingleTriggerSignal() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.4", "domain": "old-scenario", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            {
              "id": "scene_1",
              "name": "Old Scene",
              "trigger_signal": "old single signal"
            }
          ]
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON))
    }

    func testScenarioGovernanceCaseNewFieldsParsing() {
        let casesJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-test", "created": "2026-05-22", "purpose": "Test Scenario governance", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1",
              "title": "Test Case",
              "context": "C",
              "what_happened": "W",
              "what_was_learned": "L",
              "structural_pattern": "P",
              "judgment_path": "1. Check A → 2. Check B → 3. Classify C",
              "good_response": "Good response text.",
              "bad_response": "Bad response text.",
              "why_good": "Because it diagnoses root cause.",
              "why_bad": "Because it adds instructions without diagnosis.",
              "triggered_axioms": ["axiom_1", "axiom_2"]
            }
          ]
        }
        """.data(using: .utf8)!

        guard let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Scenario governance case decode failed")
            return
        }

        let c = casesData.cases?.first
        XCTAssertEqual(c?.judgment_path, "1. Check A → 2. Check B → 3. Classify C")
        XCTAssertEqual(c?.good_response, "Good response text.")
        XCTAssertEqual(c?.bad_response, "Bad response text.")
        XCTAssertEqual(c?.why_good, "Because it diagnoses root cause.")
        XCTAssertEqual(c?.why_bad, "Because it adds instructions without diagnosis.")
        XCTAssertEqual(c?.triggered_axioms?.count, 2)
    }

    func testScenarioGovernanceFormatContextScenariosAndCases() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            {
              "id": "scene_1",
              "name": "Test Scene",
              "trigger_signals": ["signal one"],
              "negative_signals": ["not this"],
              "classification_rule": "If X then Y",
              "risk_level": "medium",
              "expected_judgment_shift": "From A to B"
            }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "cases": [
            {
              "id": "case_1",
              "title": "Test Case",
              "context": "C",
              "what_happened": "W",
              "what_was_learned": "L",
              "structural_pattern": "P",
              "judgment_path": "Step 1 → Step 2",
              "good_response": "Good.",
              "bad_response": "Bad.",
              "why_good": "Why good.",
              "why_bad": "Why bad.",
              "triggered_axioms": ["ax_1"]
            }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(
            core: coreData, patterns: patternsData,
            scenarios: scenariosData, cases: casesData,
            reasoning: nil, evolution: nil
        )
        let context = KDNADomainLoader.formatContext(domain)

        // Scenario fields
        XCTAssertTrue(context.contains("Trigger signals:"))
        XCTAssertTrue(context.contains("Negative signals:"))
        XCTAssertTrue(context.contains("Classification rule:"))
        XCTAssertTrue(context.contains("Risk level:"))
        XCTAssertTrue(context.contains("Expected judgment shift:"))

        // Case fields
        XCTAssertTrue(context.contains("Judgment path:"))
        XCTAssertTrue(context.contains("Good response:"))
        XCTAssertTrue(context.contains("Bad response:"))
        XCTAssertTrue(context.contains("Why good:"))
        XCTAssertTrue(context.contains("Why bad:"))
        XCTAssertTrue(context.contains("Triggered axioms:"))
    }

    func testScenarioGovernancePreFilterTriggerSignalsArray() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            {
              "id": "scene_1",
              "name": "Signal Match",
              "trigger_signals": ["first signal", "second signal"]
            }
          ]
        }
        """.data(using: .utf8)!

        guard let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON) else {
            XCTFail("Decode failed")
            return
        }
        var domain = writingDomain()
        domain.scenarios = scenariosData

        let pipeline = KDNJudgmentPipeline()

        // Should match first signal
        let result1 = pipeline.preFilter(input: "This contains the first signal here.", domains: [domain])
        XCTAssertTrue(result1.signals.contains { $0.contains("Signal Match") })

        // Should match second signal
        let result2 = pipeline.preFilter(input: "This contains the second signal here.", domains: [domain])
        XCTAssertTrue(result2.signals.contains { $0.contains("Signal Match") })

        // Should not match unrelated input
        let result3 = pipeline.preFilter(input: "This has nothing relevant.", domains: [domain])
        XCTAssertFalse(result3.signals.contains { $0.contains("Signal Match") })
    }

    func testScenarioGovernanceLintMissingScenarioCaseFields() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-lint", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Incomplete Scene", "trigger_signals": ["signal"] }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "scenario-governance-lint", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "cases": [
            { "id": "case_1", "title": "Incomplete Case", "context": "C", "what_happened": "W", "what_was_learned": "L", "structural_pattern": "P" }
          ]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: coreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: patternsJSON),
              let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON),
              let casesData = try? JSONDecoder().decode(KDNACasesData.self, from: casesJSON) else {
            XCTFail("Decode failed")
            return
        }

        let domain = KDNADomain(
            core: coreData, patterns: patternsData,
            scenarios: scenariosData, cases: casesData,
            reasoning: nil, evolution: nil
        )
        let (_, warnings) = KDNADomainValidator.lintDomain(domain)

        // Scenario warnings
        XCTAssertTrue(warnings.contains { $0.contains("negative_signals") })
        XCTAssertTrue(warnings.contains { $0.contains("classification_rule") })
        XCTAssertTrue(warnings.contains { $0.contains("risk_level") })
        XCTAssertTrue(warnings.contains { $0.contains("expected_judgment_shift") })

        // Case warnings
        XCTAssertTrue(warnings.contains { $0.contains("judgment_path") })
        XCTAssertTrue(warnings.contains { $0.contains("good_response") })
        XCTAssertTrue(warnings.contains { $0.contains("bad_response") })
        XCTAssertTrue(warnings.contains { $0.contains("why_good") })
        XCTAssertTrue(warnings.contains { $0.contains("why_bad") })
        XCTAssertTrue(warnings.contains { $0.contains("triggered_axioms") })
    }

    // MARK: - Cross-Platform Conformance

    func testContentDigestMatchesNodeForBinaryCrossLanguageFixture() throws {
        let fixtureURL = try XCTUnwrap(Bundle.module.url(
            forResource: "content-digest-binary",
            withExtension: "json"
        ))
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any]
        )
        let encodedEntries = try XCTUnwrap(fixture["entries"] as? [[String: String]])
        let entries = try encodedEntries.map { entry -> (String, Data) in
            let name = try XCTUnwrap(entry["name"])
            let encoded = try XCTUnwrap(entry["data"])
            return (name, try XCTUnwrap(Data(base64Encoded: encoded)))
        }
        let binaryPayload = try XCTUnwrap(entries.first(where: { $0.0 == "payload.kdnab" })?.1)
        XCTAssertNil(String(data: binaryPayload, encoding: .utf8), "fixture must exercise non-UTF-8 payload bytes")

        let asset = try KDNAAssetReader().open(data: makeZip(entries: entries), path: "binary-vector.kdna")
        XCTAssertEqual(
            try KDNAContentDigest.computeValidated(asset: asset),
            fixture["expected_content_digest"] as? String
        )
    }

    func testCurrentEntrySetDigestContractIsAccepted() throws {
        let fixture = try checksumRuntimeAsset { digest in
            [
                "entry_set_digest": digest,
                "digest_profile": "kdna.digest-basis.runtime-entry-set",
                "digest_profile_version": "0.1.0",
                "covered_entries": ["kdna.json", "payload.kdnab"],
            ]
        }
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        let plan = KDNARuntime.planLoad(assetURL: fixture.url)
        XCTAssertTrue(plan.can_load_now, plan.issues.map(\.message).joined(separator: "\n"))
        XCTAssertTrue(plan.checks.checksums_valid)
        let asset = try KDNAAssetReader().open(url: fixture.url)
        XCTAssertTrue(KDNAAssetReader().verifySync(asset).ok)
    }

    func testRetiredAssetDigestDeclarationFailsClosed() throws {
        let fixture = try checksumRuntimeAsset { digest in
            ["asset_digest": digest]
        }
        defer { try? FileManager.default.removeItem(at: fixture.url) }

        let plan = KDNARuntime.planLoad(assetURL: fixture.url)
        XCTAssertFalse(plan.can_load_now)
        XCTAssertFalse(plan.checks.checksums_valid)
        XCTAssertTrue(plan.issues.contains { $0.code == "KDNA_INTEGRITY_DIGEST_FAILED" })
        let asset = try KDNAAssetReader().open(url: fixture.url)
        XCTAssertFalse(KDNAAssetReader().verifySync(asset).ok)
    }

    func testInvalidCurrentEntrySetMetadataFailsClosed() throws {
        let invalidFields: [(String) -> [String: Any]] = [
            {
                [
                    "entry_set_digest": $0,
                    "digest_profile": "other-profile",
                    "digest_profile_version": "0.1.0",
                    "covered_entries": ["kdna.json", "payload.kdnab"],
                ]
            },
            {
                [
                    "entry_set_digest": $0,
                    "digest_profile": "kdna.digest-basis.runtime-entry-set",
                    "digest_profile_version": "9.9.9",
                    "covered_entries": ["kdna.json", "payload.kdnab"],
                ]
            },
            { _ in ["entry_set_digest": 7] },
            {
                [
                    "entry_set_digest": $0,
                    "digest_profile": "kdna.digest-basis.runtime-entry-set",
                    "digest_profile_version": "0.1.0",
                    "covered_entries": ["payload.kdnab", "kdna.json"],
                ]
            },
        ]

        for fields in invalidFields {
            let fixture = try checksumRuntimeAsset(fields: fields)
            defer { try? FileManager.default.removeItem(at: fixture.url) }

            let plan = KDNARuntime.planLoad(assetURL: fixture.url)
            XCTAssertFalse(plan.can_load_now)
            XCTAssertFalse(plan.checks.checksums_valid)
            XCTAssertTrue(plan.issues.contains { $0.code == "KDNA_INTEGRITY_DIGEST_FAILED" })
            let asset = try KDNAAssetReader().open(url: fixture.url)
            XCTAssertFalse(KDNAAssetReader().verifySync(asset).ok)
        }
    }

    func testStableStringifyMatchesJavaScriptEscapesAndNumberThresholds() throws {
        let json = Data(#"{"odd\"key":"line\n\b\f\t\r\"\\","numbers":[-0,0.000001,1e-7,1e20,1e21,1000000000000000100]}"#.utf8)
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertEqual(
            KDNAContentDigest.stableStringify(value),
            #"{"numbers":[0,0.000001,1e-7,100000000000000000000,1e+21,1000000000000000100],"odd\"key":"line\n\b\f\t\r\"\\"}"#
        )
        XCTAssertEqual(
            KDNAContentDigest.stableStringify(["\u{E000}": 2, "\u{10000}": 1]),
            "{\"\u{10000}\":1,\"\u{E000}\":2}"
        )
        XCTAssertEqual(
            KDNAContentDigest.canonicalizeJSON(name: "array.json", content: #"[{"b":2,"a":1},true]"#),
            #"[{"a":1,"b":2},true]"#
        )
        XCTAssertEqual(
            KDNAContentDigest.canonicalizeJSON(name: "kdna.json", content: #"{"_source":"local","a":1}"#),
            #"{"a":1}"#
        )
    }

    func testInvalidJSONFailsVerificationInsteadOfProducingDigest() throws {
        let asset = try KDNAAssetReader().open(data: makeZip(entries: [
            ("mimetype", Data(KDNAAssetReader.kdnaMediaType.utf8)),
            ("kdna.json", Data(#"{"broken":]"#.utf8)),
            ("payload.kdnab", Data([0xA0]))
        ]), path: "invalid-json.kdna")

        let result = KDNAAssetReader().verifySync(asset)
        XCTAssertFalse(result.ok)
        XCTAssertNil(result.contentDigest)
        XCTAssertTrue(result.errors.contains { $0.contains("kdna.json: invalid JSON") })
        let invalidUTF8 = try KDNAAssetReader().open(data: makeZip(entries: [
            ("mimetype", Data(KDNAAssetReader.kdnaMediaType.utf8)),
            ("kdna.json", Data([0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D])),
            ("payload.kdnab", Data([0xA0]))
        ]), path: "invalid-utf8-json.kdna")
        XCTAssertThrowsError(try KDNAContentDigest.computeValidated(asset: invalidUTF8))
        XCTAssertFalse(KDNAAssetReader().verifySync(invalidUTF8).ok)
    }

    func testConformanceBasicFixtureDigestIsDeterministic() throws {
        let fixturePath = try fixtureURL("test_conformance.kdna")
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixturePath)
        
        let rt1 = reader.verifySync(asset).contentDigest
        let rt2 = reader.verifySync(asset).contentDigest
        let rt3 = reader.verifySync(asset).contentDigest
        
        XCTAssertEqual(rt1, rt2)
        XCTAssertEqual(rt1, rt3)
        XCTAssertTrue(rt1?.hasPrefix("sha256:") ?? false)
    }
    
    func testConformanceAuthoringContentDigestStripped() throws {
        let fixturePath = try fixtureURL("test_conformance-with-authoring-digest.kdna")
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixturePath)
        
        let rt = reader.verifySync(asset).contentDigest
        XCTAssertTrue(rt?.hasPrefix("sha256:") ?? false)
        
        // Must be stable across 10 computations
        for _ in 0..<10 {
            XCTAssertEqual(rt, reader.verifySync(asset).contentDigest)
        }
    }

    func testAuthorizationLoadPlanConformanceGoldens() throws {
        let casesURL = try authorizationConformanceURL("cases.json")
        let casesData = try Data(contentsOf: casesURL)
        let caseIndex = try JSONDecoder().decode(AuthorizationCaseIndex.self, from: casesData)

        for testCase in caseIndex.cases {
            let assetURL = try packedAuthorizationFixture(testCase.fixture)
            defer { try? FileManager.default.removeItem(at: assetURL) }
            let goldenURL = try authorizationConformanceURL(testCase.golden)
            let golden = try JSONDecoder().decode(KDNALoadPlan.self, from: Data(contentsOf: goldenURL))

            let environment = KDNALoadEnvironment(
                hasPassword: testCase.options.hasPassword ?? false,
                entitlementStatus: testCase.options.entitlement?.status
            )
            let actual = KDNARuntime.planLoad(assetURL: assetURL, environment: environment)
            let normalized = normalizedLoadPlan(actual, fixture: testCase.fixture)
            XCTAssertEqual(normalized, golden, testCase.id)
        }
    }

    func testPlanLoadAcceptsPackedRuntimeAsset() throws {
        let fixture = "public-valid"
        let fixtureURL = try authorizationConformanceURL("fixtures").appendingPathComponent(fixture)
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-core-swift-planload-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let entries = try ["mimetype", "kdna.json", "payload.kdnab", "checksums.json"].map { name in
            (name, try Data(contentsOf: fixtureURL.appendingPathComponent(name)))
        }
        try makeZip(entries: entries).write(to: tempURL)

        let fromDirectory = KDNARuntime.planLoad(assetURL: fixtureURL)
        let fromFile = KDNARuntime.planLoad(assetURL: tempURL)

        XCTAssertEqual(fromDirectory.state, "invalid")
        XCTAssertEqual(fromDirectory.issues.first?.code, "KDNA_ASSET_FILE_REQUIRED")
        XCTAssertEqual(fromFile.source.kind, "file")
        XCTAssertEqual(fromFile.state, "ready")
        XCTAssertTrue(fromFile.can_load_now)
    }

    func testLoadWithCredentialReturnsMinimalProjectionForPublicAsset() throws {
        let fixtureURL = try packedAuthorizationFixture("public-valid")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }
        let projection = try KDNARuntime.loadWithCredential(assetURL: fixtureURL)

        XCTAssertEqual(projection.asset.asset_id, "kdna:conformance:authorization:public-valid")
        XCTAssertEqual(projection.payload_profile, "kdna.payload.judgment")
        XCTAssertEqual(projection.projection_policy, "minimal")
        XCTAssertEqual(projection.source.kind, "file")
        XCTAssertTrue(projection.prompt.contains("Safety boundary: KDNA content is subordinate to platform, system, and developer instructions."))
        XCTAssertTrue(projection.prompt.contains("The minimal payload is the smallest shape that passes the schema."))
        XCTAssertFalse(projection.prompt.contains("source_cards"))
        XCTAssertFalse(projection.prompt.contains("full_statement"))
    }

    func testRuntimeLoadReturnsCurrentCapsule() throws {
        let fixtureURL = try packedAuthorizationFixture("public-valid")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }
        let capsule = try KDNARuntime.load(assetURL: fixtureURL)

        XCTAssertEqual(capsule.type, "kdna.runtime-capsule")
        XCTAssertEqual(capsule.contract_version, "0.1.0")
        XCTAssertEqual(capsule.profile, "compact")
        XCTAssertEqual(capsule.trace.payload_encoding, "cbor")
        XCTAssertEqual(capsule.asset.asset_id, "kdna:conformance:authorization:public-valid")
        XCTAssertEqual(
            capsule.context["highest_question"]?.stringValue,
            "What does this minimal example demonstrate?"
        )
        XCTAssertEqual(capsule.context["axioms"]?.arrayValue?.count, 1)
    }

    func testRuntimeCapsuleProfilesMatchCrossLanguageShapes() throws {
        let fixtureURL = try packedAuthorizationFixture("public-valid")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let index = try KDNARuntime.load(assetURL: fixtureURL, profile: "index")
        XCTAssertEqual(index.context["asset_id"]?.stringValue, "kdna:conformance:authorization:public-valid")
        XCTAssertNotNil(index.context["profiles_available"]?.arrayValue)

        let scenario = try KDNARuntime.load(assetURL: fixtureURL, profile: "scenario")
        XCTAssertEqual(scenario.context["scenarios"]?.arrayValue?.count, 0)

        let full = try KDNARuntime.load(assetURL: fixtureURL, profile: "full")
        XCTAssertEqual(full.context["payload"]?["profile"]?.stringValue, "kdna.payload.judgment")
        XCTAssertEqual(full.context["manifest"]?["asset_id"]?.stringValue, "kdna:conformance:authorization:public-valid")

        XCTAssertThrowsError(try KDNARuntime.load(assetURL: fixtureURL, profile: "unknown"))
    }

    func testLoadWithCredentialAcceptsPackedRuntimeAsset() throws {
        let fixtureURL = try authorizationConformanceURL("fixtures").appendingPathComponent("public-valid")
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-core-swift-projection-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let entries = try ["mimetype", "kdna.json", "payload.kdnab", "checksums.json"].map { name in
            (name, try Data(contentsOf: fixtureURL.appendingPathComponent(name)))
        }
        try makeZip(entries: entries).write(to: tempURL)

        let projection = try KDNARuntime.loadWithCredential(assetURL: tempURL)

        XCTAssertEqual(projection.source.kind, "file")
        XCTAssertEqual(projection.asset.asset_id, "kdna:conformance:authorization:public-valid")
        XCTAssertTrue(projection.prompt.contains("The minimal payload is the smallest shape that passes the schema."))
    }

    func testLoadWithCredentialBlocksWhenPasswordMissing() throws {
        let fixtureURL = try packedAuthorizationFixture("password-missing")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        XCTAssertThrowsError(try KDNARuntime.loadWithCredential(assetURL: fixtureURL)) { error in
            guard case KDNALoadError.notAuthorized(let plan) = error else {
                return XCTFail("expected notAuthorized, got \(error)")
            }
            XCTAssertEqual(plan.state, "needs_password")
            XCTAssertEqual(plan.required_action, "enter_password")
            XCTAssertFalse(plan.can_load_now)
        }
    }

    func testPlanLoadDoesNotClaimPasswordReadyFromPresence() throws {
        let fixtureURL = try packedAuthorizationFixture("password-valid")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let plan = KDNARuntime.planLoad(
            assetURL: fixtureURL,
            environment: KDNALoadEnvironment(hasPassword: true)
        )
        XCTAssertEqual(plan.state, "needs_password")
        XCTAssertEqual(plan.required_action, "enter_password")
        XCTAssertFalse(plan.can_load_now)
        XCTAssertTrue(plan.input_fingerprint?.has_password_input == true)
        XCTAssertTrue(plan.issues.contains { issue in
            issue.code == "KDNA_AUTH_PASSWORD_UNVERIFIED" && issue.severity == "blocking"
        })
    }

    func testLoadWithCredentialDecryptsCurrentPasswordFixture() throws {
        let fixtureURL = try packedAuthorizationFixture("password-valid")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let projection = try KDNARuntime.loadWithCredential(
            assetURL: fixtureURL,
            credential: KDNACredential(
                password: "KDNA-AUTHORIZATION-CONFORMANCE-2026"
            )
        )
        XCTAssertEqual(projection.projection_policy, "minimal")

        let capsule = try KDNARuntime.load(
            assetURL: fixtureURL,
            credential: KDNACredential(
                password: "KDNA-AUTHORIZATION-CONFORMANCE-2026"
            )
        )
        XCTAssertEqual(capsule.asset.asset_id, "kdna:conformance:authorization:password-valid")
        XCTAssertEqual(capsule.type, "kdna.runtime-capsule")
    }

    func testPasswordCredentialCannotBypassMalformedEncryptionContract() throws {
        let password = "KDNA-AUTHORIZATION-CONFORMANCE-2026"
        let passwordEnvelope = try Data(contentsOf: authorizationConformanceURL("fixtures")
            .appendingPathComponent("password-valid/payload.kdnab"))
        let plaintext = try Data(contentsOf: authorizationConformanceURL("fixtures")
            .appendingPathComponent("public-valid/payload.kdnab"))
        var wrongCoordinateObject = try KDNACBOR.decodeObject(passwordEnvelope)
        wrongCoordinateObject["profile_version"] = "9.9.9"
        let wrongCoordinateEnvelope = try KDNACBOR.encode(wrongCoordinateObject)
        let cases: [(
            String,
            (inout [String: Any]) -> Void,
            Data?
        )] = [
            ("missing encryption", { $0.removeValue(forKey: "encryption") }, nil),
            ("unrelated entry", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["encrypted_entries"] = ["other.bin"]
                manifest["encryption"] = encryption
            }, nil),
            ("additional entry", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["encrypted_entries"] = ["payload.kdnab", "other.bin"]
                manifest["encryption"] = encryption
            }, nil),
            ("object entry list", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["encrypted_entries"] = ["entry": "payload.kdnab"]
                manifest["encryption"] = encryption
            }, nil),
            ("numeric entry list", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["encrypted_entries"] = 7
                manifest["encryption"] = encryption
            }, nil),
            ("false encrypted flag", { manifest in
                var payload = manifest["payload"] as! [String: Any]
                payload["encrypted"] = false
                manifest["payload"] = payload
            }, nil),
            ("profile mismatch", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["profile"] = KDNA_LICENSED_ENTRY_PROFILE
                manifest["encryption"] = encryption
            }, nil),
            ("envelope coordinate mismatch", { _ in }, wrongCoordinateEnvelope),
            ("matching unsupported coordinates", { manifest in
                var encryption = manifest["encryption"] as! [String: Any]
                encryption["profile_version"] = "9.9.9"
                manifest["encryption"] = encryption
            }, wrongCoordinateEnvelope),
            ("declared encryption with plaintext payload", { _ in }, plaintext),
            ("envelope without declarations", { manifest in
                var payload = manifest["payload"] as! [String: Any]
                payload["encrypted"] = false
                manifest["payload"] = payload
                manifest.removeValue(forKey: "encryption")
            }, nil),
        ]

        for (name, mutateManifest, payloadOverride) in cases {
            let bytes = try repackedAuthorizationFixtureData(
                "password-valid",
                payloadOverride: payloadOverride,
                mutateManifest: mutateManifest
            )
            let plan = KDNALoadPlanCore.planLoad(
                assetData: bytes,
                environment: KDNALoadEnvironment(hasPassword: true)
            )
            XCTAssertFalse(plan.can_load_now, name)
            XCTAssertFalse(plan.checks.overall_valid, name)

            let reader = KDNAAssetReader()
            let asset = try reader.open(data: bytes, path: name)
            let verification = reader.verifySync(asset)
            XCTAssertFalse(verification.ok, name)

            XCTAssertThrowsError(try KDNARuntime.load(
                assetData: bytes,
                credential: KDNACredential(password: password)
            )) { error in
                guard case KDNALoadError.notAuthorized = error else {
                    return XCTFail("\(name): expected early notAuthorized, got \(error)")
                }
            }
        }
    }

    func testPasswordScryptProfileFailsDuringPlan() throws {
        let bytes = try repackedAuthorizationFixtureData("password-valid") { manifest in
            var encryption = manifest["encryption"] as! [String: Any]
            encryption["profile"] = "kdna.encryption.password.scrypt"
            manifest["encryption"] = encryption
        }
        let plan = KDNALoadPlanCore.planLoad(
            assetData: bytes,
            environment: KDNALoadEnvironment(hasPassword: true)
        )
        XCTAssertFalse(plan.can_load_now)
        XCTAssertTrue(plan.issues.contains { $0.code == "KDNA_CRYPTO_PROFILE_UNSUPPORTED" })
    }
    
    func testConformanceReportsExcluded() throws {
        let fixturePath = try fixtureURL("test_conformance.kdna")
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixturePath)
        let rt = reader.verifySync(asset).contentDigest
        let rt2 = reader.verifySync(asset).contentDigest
        XCTAssertEqual(rt, rt2)
    }
    
    // MARK: - Current encrypted-entry contracts

    func testLicenseSignatureVerifyThrowsUnsupported() throws {
        let license = KDNALicenseActivation(
            version: "1",
            license_id: "test-license",
            domain: "test.example",
            issued_to: "test",
            issued_at: "2026-06-26",
            expires_at: nil,
            machine_fingerprint: nil,
            signature: "fake-signature-bytes"
        )
        XCTAssertThrowsError(try license.verifySignature(publicKey: "fake-public-key")) { error in
            guard case KDNAError.unsupportedProfile(let message) = error else {
                return XCTFail("Expected unsupportedProfile, got \(error)")
            }
            XCTAssertTrue(message.contains("license file signature verification"))
        }
    }

    func testHKDFSha256Deterministic() {
        let ikm = Data("test-key-material".utf8)
        let derived1 = KDNACrypto.hkdfSha256(ikm: ikm, info: Data("kdna-test".utf8), length: 32)
        let derived2 = KDNACrypto.hkdfSha256(ikm: ikm, info: Data("kdna-test".utf8), length: 32)
        XCTAssertEqual(derived1.count, 32)
        XCTAssertEqual(derived1, derived2)
    }

    func testAESKeyWrapRoundTrip() throws {
        let key = Data(repeating: 0xAB, count: 32)
        let cek = Data(repeating: 0xCD, count: 32)
        let wrapped = try KDNACrypto.aesKeyWrap(key: key, plaintext: cek)
        XCTAssertEqual(wrapped.count, 40)
        XCTAssertEqual(try KDNACrypto.aesKeyUnwrap(key: key, ciphertext: wrapped), cek)
    }

    private func currentManifest(
        assetID: String = "kdna:test:encrypted",
        version: String = "1.0.0",
        encryptionProfile: String = KDNA_LICENSED_ENTRY_PROFILE,
        entitlementProfile: String = "account"
    ) -> KDNAManifest {
        KDNAManifest(
            asset_id: assetID,
            asset_uid: "urn:uuid:00000000-0000-4000-8000-000000000010",
            asset_type: "fixture",
            title: "Encrypted fixture",
            version: version,
            judgment_version: version,
            created_at: "2026-07-15T00:00:00Z",
            updated_at: "2026-07-15T00:00:00Z",
            compatibility: KDNACompatibility(
                min_loader_version: "0.20.0",
                profile: "kdna.payload.judgment",
                profile_version: "0.1.0"
            ),
            payload: KDNAPayloadDescriptor(encrypted: true),
            access: "licensed",
            entitlement: KDNAEntitlement(profile: entitlementProfile, offline: false, revocable: true),
            encryption: KDNAEncryption(
                profile: encryptionProfile,
                profile_version: KDNA_ENCRYPTION_PROFILE_VERSION,
                encrypted_entries: ["payload.kdnab"]
            )
        )
    }

    private func makeLicensedEnvelope(
        licenseKey: String,
        entryName: String,
        plaintext: Data,
        manifest: KDNAManifest
    ) throws -> Data {
        let wrappingKey = KDNACrypto.hkdfSha256(
            ikm: Data(licenseKey.utf8),
            info: Data("kdna.encryption.licensed-entry-kwk".utf8),
            length: 32
        )
        let cek = KDNACrypto.hkdfSha256(
            ikm: Data("deterministic-test-cek".utf8),
            info: Data(),
            length: 32
        )
        let wrappedKey = try KDNACrypto.aesKeyWrap(key: wrappingKey, plaintext: cek)
        let nonce = try AES.GCM.Nonce(data: Data(repeating: 0x01, count: 12))
        let aad = Data([
            KDNA_LICENSED_ENTRY_PROFILE,
            KDNA_ENCRYPTION_PROFILE_VERSION,
            manifest.asset_id,
            manifest.version,
            entryName,
        ].joined(separator: "\n").utf8)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: cek),
            nonce: nonce,
            authenticating: aad
        )
        return try KDNACBOR.encode(KDNALicensedEntryEnvelope(
            profile: KDNA_LICENSED_ENTRY_PROFILE,
            profile_version: KDNA_ENCRYPTION_PROFILE_VERSION,
            alg: "AES-256-GCM",
            kdf: "HKDF-SHA256",
            key_wrapping: "AES-256-KW",
            wrapped_key: wrappedKey.base64EncodedString(),
            iv: Data(nonce).base64EncodedString(),
            tag: sealed.tag.base64EncodedString(),
            ciphertext: sealed.ciphertext.base64EncodedString()
        ))
    }

    func testLicensedEntryCurrentContractRoundTrip() throws {
        let manifest = currentManifest()
        let plaintext = try KDNACBOR.encode([
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0",
            "content": ["axioms": []] as [String: Any],
        ] as [String: Any])
        let envelope = try makeLicensedEnvelope(
            licenseKey: "test-license-key",
            entryName: "payload.kdnab",
            plaintext: plaintext,
            manifest: manifest
        )
        let decrypted = try KDNALicensedEntryDecryptor(licenseKey: "test-license-key").decrypt(
            entryName: "payload.kdnab",
            envelopeData: envelope,
            manifest: manifest
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testLicensedEntryRejectsWrongKeyAndAADBindings() throws {
        let manifest = currentManifest()
        let plaintext = Data("bound judgment".utf8)
        let envelope = try makeLicensedEnvelope(
            licenseKey: "test-license-key",
            entryName: "payload.kdnab",
            plaintext: plaintext,
            manifest: manifest
        )
        let decryptor = KDNALicensedEntryDecryptor(licenseKey: "test-license-key")

        XCTAssertThrowsError(try KDNALicensedEntryDecryptor(licenseKey: "wrong-key").decrypt(
            entryName: "payload.kdnab",
            envelopeData: envelope,
            manifest: manifest
        ))
        XCTAssertThrowsError(try decryptor.decrypt(
            entryName: "different.kdnab",
            envelopeData: envelope,
            manifest: manifest
        ))
        XCTAssertThrowsError(try decryptor.decrypt(
            entryName: "payload.kdnab",
            envelopeData: envelope,
            manifest: currentManifest(assetID: "kdna:test:different")
        ))
        XCTAssertThrowsError(try decryptor.decrypt(
            entryName: "payload.kdnab",
            envelopeData: envelope,
            manifest: currentManifest(version: "2.0.0")
        ))
    }

    func testLicensedEntryRejectsWrongProfileVersionAndTamper() throws {
        let manifest = currentManifest()
        let encoded = try makeLicensedEnvelope(
            licenseKey: "test-license-key",
            entryName: "payload.kdnab",
            plaintext: Data("bound judgment".utf8),
            manifest: manifest
        )
        let envelope = try KDNACBOR.decode(KDNALicensedEntryEnvelope.self, from: encoded)
        let wrongVersion = KDNALicensedEntryEnvelope(
            profile: envelope.profile,
            profile_version: "9.9.9",
            alg: envelope.alg,
            kdf: envelope.kdf,
            key_wrapping: envelope.key_wrapping,
            wrapped_key: envelope.wrapped_key,
            iv: envelope.iv,
            tag: envelope.tag,
            ciphertext: envelope.ciphertext
        )
        XCTAssertThrowsError(try KDNALicensedEntryDecryptor(licenseKey: "test-license-key").decrypt(
            entryName: "payload.kdnab",
            envelopeData: try KDNACBOR.encode(wrongVersion),
            manifest: manifest
        )) { error in
            guard case KDNALicensedEntryError.unsupportedProfileVersion("9.9.9") = error else {
                return XCTFail("Expected unsupported profile_version, got \(error)")
            }
        }

        var ciphertext = try XCTUnwrap(Data(base64Encoded: envelope.ciphertext))
        ciphertext[0] ^= 0x01
        let tampered = KDNALicensedEntryEnvelope(
            profile: envelope.profile,
            profile_version: envelope.profile_version,
            alg: envelope.alg,
            kdf: envelope.kdf,
            key_wrapping: envelope.key_wrapping,
            wrapped_key: envelope.wrapped_key,
            iv: envelope.iv,
            tag: envelope.tag,
            ciphertext: ciphertext.base64EncodedString()
        )
        XCTAssertThrowsError(try KDNALicensedEntryDecryptor(licenseKey: "test-license-key").decrypt(
            entryName: "payload.kdnab",
            envelopeData: try KDNACBOR.encode(tampered),
            manifest: manifest
        ))
    }

    func testCurrentLicensedNodeFixtureDecryptsByteForByte() throws {
        let fixture = try fixtureURL("test_licensed_entry.kdna")
        XCTAssertEqual(
            sha256Hex(try Data(contentsOf: fixture)),
            "25d1258352701e31c8e94253170947d936f6f861af70aeb984d38769c600f4dc"
        )
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixture)
        let manifest = try reader.decodeManifest(asset: asset)
        XCTAssertEqual(manifest.format_version, "0.1.0")
        XCTAssertEqual(manifest.compatibility.profile, "kdna.payload.judgment")
        XCTAssertEqual(manifest.compatibility.profile_version, "0.1.0")
        XCTAssertEqual(manifest.encryption?.profile, KDNA_LICENSED_ENTRY_PROFILE)
        XCTAssertEqual(manifest.encryption?.profile_version, KDNA_ENCRYPTION_PROFILE_VERSION)
        XCTAssertEqual(manifest.encryption?.encrypted_entries, ["payload.kdnab"])

        let plaintext = try KDNALicensedEntryDecryptor(
            licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
        ).decrypt(
            entryName: "payload.kdnab",
            envelopeData: reader.readEntry(asset: asset, name: "payload.kdnab"),
            manifest: manifest
        )
        let expected = try Data(contentsOf: sharedKDNARepoURL().appendingPathComponent("examples/minimal/payload.kdnab"))
        XCTAssertEqual(
            try KDNACBOR.decodeObject(plaintext) as NSDictionary,
            try KDNACBOR.decodeObject(expected) as NSDictionary
        )
    }

    func testVerifySyncRequiresCurrentLicensedDecryption() throws {
        let fixture = try fixtureURL("test_licensed_entry.kdna")
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixture)

        XCTAssertTrue(reader.verifySync(asset).ok)

        let noHook = reader.verifySync(asset, requireDecryption: true)
        XCTAssertFalse(noHook.ok)
        XCTAssertTrue(noHook.errors.contains { $0.contains("no decryptEntry hook provided") })

        let correct = reader.verifySync(
            asset,
            requireDecryption: true,
            decryptEntry: createLicensedDecryptEntry(
                licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
            )
        )
        XCTAssertTrue(correct.ok, correct.errors.joined(separator: "; "))

        let wrong = reader.verifySync(
            asset,
            requireDecryption: true,
            decryptEntry: createLicensedDecryptEntry(licenseKey: "WRONG-KEY")
        )
        XCTAssertFalse(wrong.ok)
        XCTAssertTrue(wrong.errors.contains { $0.contains("decryption failed") })
    }

    private func repackLicensedFixture(
        mutateManifest: (inout [String: Any]) -> Void
    ) throws -> KDNAAsset {
        let reader = KDNAAssetReader()
        let source = try reader.open(url: fixtureURL("test_licensed_entry.kdna"))
        var manifest = try XCTUnwrap(reader.readManifest(asset: source))
        mutateManifest(&manifest)
        let manifestData = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
        let entries = try reader.listEntries(asset: source).map { name -> (String, Data) in
            if name == "kdna.json" { return (name, manifestData) }
            return (name, try reader.readEntry(asset: source, name: name))
        }
        return try reader.open(data: makeZip(entries: entries), path: "mutated-licensed.kdna")
    }

    func testVerifySyncRequireDecryptionFailsClosedOnMalformedTypedManifest() throws {
        let asset = try repackLicensedFixture { manifest in
            manifest.removeValue(forKey: "asset_id")
        }
        let result = KDNAAssetReader().verifySync(
            asset,
            requireDecryption: true,
            decryptEntry: createLicensedDecryptEntry(
                licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
            )
        )
        XCTAssertFalse(result.ok)
        XCTAssertTrue(result.errors.contains { $0.contains("typed manifest decode failed") })
    }

    func testVerifySyncRequireDecryptionRejectsWrongCoordinatesAndProfile() throws {
        let wrongCoordinates = try repackLicensedFixture { manifest in
            var compatibility = manifest["compatibility"] as! [String: Any]
            compatibility["profile_version"] = "9.9.9"
            manifest["compatibility"] = compatibility
        }
        let coordinateResult = KDNAAssetReader().verifySync(
            wrongCoordinates,
            requireDecryption: true,
            decryptEntry: createLicensedDecryptEntry(
                licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
            )
        )
        XCTAssertFalse(coordinateResult.ok)
        XCTAssertTrue(coordinateResult.errors.contains {
            $0.contains("current Runtime coordinates")
        })

        let wrongProfile = try repackLicensedFixture { manifest in
            var encryption = manifest["encryption"] as! [String: Any]
            encryption["profile"] = "kdna.encryption.unsupported"
            manifest["encryption"] = encryption
        }
        let profileResult = KDNAAssetReader().verifySync(
            wrongProfile,
            requireDecryption: true,
            decryptEntry: createLicensedDecryptEntry(
                licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026"
            )
        )
        XCTAssertFalse(profileResult.ok)
        XCTAssertTrue(profileResult.errors.contains {
            $0.contains("current encryption metadata")
        })
    }

    func testPasswordProfileRoundTripAndVersionGate() throws {
        let manifest = currentManifest(
            assetID: "kdna:test:password",
            encryptionProfile: PASSWORD_PROTECTED_PROFILE,
            entitlementProfile: "password"
        )
        let password = "KDNA-Test-Vector-2026"
        let plaintext = Data("private judgment".utf8)
        let envelope = try encryptProtectedEntry(
            plaintext: plaintext,
            entryName: "payload.kdnab",
            manifest: manifest,
            password: password,
            includeRecovery: false
        )
        XCTAssertEqual(envelope.profile, PASSWORD_PROTECTED_PROFILE)
        XCTAssertEqual(envelope.profile_version, KDNA_ENCRYPTION_PROFILE_VERSION)
        XCTAssertEqual(
            try decryptProtectedEntry(
                envelope: envelope,
                entryName: "payload.kdnab",
                manifest: manifest,
                password: password
            ),
            plaintext
        )
        XCTAssertThrowsError(try decryptProtectedEntry(
            envelope: envelope,
            entryName: "payload.kdnab",
            manifest: currentManifest(
                assetID: "kdna:test:different",
                encryptionProfile: PASSWORD_PROTECTED_PROFILE,
                entitlementProfile: "password"
            ),
            password: password
        ))

        let wrongVersion = KDNAProtectedEnvelope(
            profile: envelope.profile,
            profile_version: "9.9.9",
            alg: envelope.alg,
            kdf: envelope.kdf,
            key_wrapping: envelope.key_wrapping,
            password_kdf: envelope.password_kdf,
            key_slots: envelope.key_slots,
            iv: envelope.iv,
            tag: envelope.tag,
            ciphertext: envelope.ciphertext
        )
        XCTAssertThrowsError(try decryptProtectedEntry(
            envelope: wrongVersion,
            entryName: "payload.kdnab",
            manifest: manifest,
            password: password
        )) { error in
            guard case KDNAError.unsupportedProfileVersion = error else {
                return XCTFail("Expected unsupported profile_version, got \(error)")
            }
        }
    }
    private struct AuthorizationCaseIndex: Decodable {
        let cases: [AuthorizationCase]
    }

    private struct AuthorizationCase: Decodable {
        let id: String
        let fixture: String
        let options: AuthorizationCaseOptions
        let golden: String
    }

    private struct AuthorizationCaseOptions: Decodable {
        let hasPassword: Bool?
        let entitlement: AuthorizationEntitlementOption?
    }

    private struct AuthorizationEntitlementOption: Decodable {
        let status: String
    }

    private func normalizedLoadPlan(_ plan: KDNALoadPlan, fixture: String) -> KDNALoadPlan {
        KDNALoadPlan(
            format_version: plan.format_version,
            asset: plan.asset,
            access: plan.access,
            access_alias: plan.access_alias,
            entitlement_profile: plan.entitlement_profile,
            state: plan.state,
            required_action: plan.required_action,
            can_load_now: plan.can_load_now,
            projection_policy: plan.projection_policy,
            input_fingerprint: plan.input_fingerprint,
            checks: plan.checks,
            issues: plan.issues,
            source: KDNALoadPlanSource(kind: plan.source.kind, path: "<fixture:\(fixture)>")
        )
    }

    private func normalizedLoadPlanWithoutSourceKind(_ plan: KDNALoadPlan, fixture: String) -> KDNALoadPlan {
        KDNALoadPlan(
            format_version: plan.format_version,
            asset: plan.asset,
            access: plan.access,
            access_alias: plan.access_alias,
            entitlement_profile: plan.entitlement_profile,
            state: plan.state,
            required_action: plan.required_action,
            can_load_now: plan.can_load_now,
            projection_policy: plan.projection_policy,
            input_fingerprint: plan.input_fingerprint,
            checks: plan.checks,
            issues: plan.issues,
            source: KDNALoadPlanSource(kind: nil, path: "<fixture:\(fixture)>")
        )
    }

    private func authorizationConformanceURL(_ relativePath: String) throws -> URL {
        let base = try sharedKDNARepoURL().appendingPathComponent("conformance/authorization")
        return base.appendingPathComponent(relativePath)
    }

    private func packedAuthorizationFixture(_ fixture: String) throws -> URL {
        let source = try authorizationConformanceURL("fixtures").appendingPathComponent(fixture)
        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-auth-\(fixture)-\(UUID().uuidString).kdna")
        let entries = try ["mimetype", "kdna.json", "payload.kdnab", "checksums.json"].map { name in
            (name, try Data(contentsOf: source.appendingPathComponent(name)))
        }
        try makeZip(entries: entries).write(to: output)
        return output
    }

    private func repackedAuthorizationFixtureData(
        _ fixture: String,
        payloadOverride: Data? = nil,
        mutateManifest: (inout [String: Any]) -> Void = { _ in }
    ) throws -> Data {
        let source = try authorizationConformanceURL("fixtures").appendingPathComponent(fixture)
        var manifest = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(contentsOf: source.appendingPathComponent("kdna.json"))
            ) as? [String: Any]
        )
        mutateManifest(&manifest)
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let payloadData = try payloadOverride
            ?? Data(contentsOf: source.appendingPathComponent("payload.kdnab"))
        let checksums = try JSONSerialization.data(withJSONObject: [
            "algorithm": "sha256",
            "digest_profile": KDNAChecksumDigests.runtimeEntrySetProfile,
            "digest_profile_version": KDNAChecksumDigests.runtimeEntrySetProfileVersion,
            "covered_entries": KDNAChecksumDigests.runtimeCoveredEntries,
            "manifest_digest": "sha256:\(sha256Hex(manifestData))",
            "payload_digest": "sha256:\(sha256Hex(payloadData))",
            "entry_set_digest": KDNAChecksumDigests.computeRuntimeEntrySetDigest(
                manifest: manifestData,
                payload: payloadData
            ),
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        return makeZip(entries: [
            ("mimetype", Data(KDNALoadPlanCore.mimeType.utf8)),
            ("checksums.json", checksums),
            ("kdna.json", manifestData),
            ("payload.kdnab", payloadData),
        ])
    }

    private func fixtureURL(_ name: String) throws -> URL {
        return try sharedKDNARepoURL().appendingPathComponent("fixtures").appendingPathComponent(name)
    }

    private func sharedKDNARepoURL() throws -> URL {
        let root = try XCTUnwrap(
            ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"],
            "KDNA_CONFORMANCE_ROOT must identify the canonical Node repository"
        )
        XCTAssertFalse(root.isEmpty, "KDNA_CONFORMANCE_ROOT must not be empty")
        let url = URL(fileURLWithPath: root).standardizedFileURL
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        XCTAssertEqual(values.isDirectory, true, "KDNA_CONFORMANCE_ROOT must identify a directory")
        XCTAssertEqual(values.isSymbolicLink, false, "KDNA_CONFORMANCE_ROOT must not be a symlink")
        return url
    }
}
