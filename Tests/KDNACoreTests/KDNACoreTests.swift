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

    // MARK: - Test Fixtures

    func testAssetReaderAcceptsCoreV1RuntimeContainer() throws {
        let manifestData = Data("""
        {
          "kdna_version": "1.0",
          "name": "@test/runtime",
          "asset_id": "kdna:test:runtime",
          "asset_uid": "urn:uuid:00000000-0000-4000-8000-000000000001",
          "asset_type": "domain",
          "title": "Runtime",
          "version": "1.0.0",
          "judgment_version": "1.0.0",
          "access": "public",
          "payload": {
            "path": "payload.kdnab",
            "encoding": "json",
            "encrypted": false
          }
        }
        """.utf8)
        let payloadData = Data(#"{"profile":"judgment-profile-v1","core":{"axioms":[]}}"#.utf8)
        let checksumsData = Data(#"{"algorithm":"sha256"}"#.utf8)
        let zipData = makeZip(entries: [
            ("mimetype", Data(KDNAAssetReader.coreV1MediaType.utf8)),
            ("kdna.json", manifestData),
            ("payload.kdnab", payloadData),
            ("checksums.json", checksumsData),
        ])

        let reader = KDNAAssetReader()
        let asset = try reader.open(data: zipData, path: "runtime.kdna")
        let result = reader.verifySync(asset)

        XCTAssertEqual(reader.mediaType(asset: asset), KDNAAssetReader.coreV1MediaType)
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
          "stances": ["Never use vague adjectives", "Always start with the reader's problem"],
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
          "trigger_signals": []
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
          "stances": ["Always reject unverified input", "Never trust client-side validation"],
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
          "stances": ["Never start with the reader's problem"],
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
          "stances": ["S1"], "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
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
          "kdna_spec": "1.0-rc",
          "name": "test-domain",
          "version": "0.1.0",
          "status": "experimental",
          "eval_score": 0.85,
          "test_count": 12,
          "quality_badge": "community"
        }
        """.data(using: .utf8)!
        try? manifestJSON.write(to: tempDir.appendingPathComponent("kdna.json"))

        let manifest = KDNADomainLoader.loadManifest(from: tempDir.path)
        XCTAssertNotNil(manifest)
        XCTAssertEqual(manifest?.name, "test-domain")
        XCTAssertEqual(manifest?.eval_score, 0.85)
        XCTAssertEqual(manifest?.quality_badge, "community")
    }

    func testOldFieldNameDetection() {
        let obj: [String: Any] = [
            "statement": "old field",
            "nested": [
                "description": "another old field"
            ]
        ]
        let warnings = KDNADomainLoader.detectOldFieldNames(obj, domainName: "test")
        XCTAssertFalse(warnings.isEmpty)
        XCTAssertTrue(warnings.contains { $0.contains("statement") })
        XCTAssertTrue(warnings.contains { $0.contains("description") })
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
          "stances": ["S1"], "axioms": [], "ontology": [], "frameworks": []
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
          "stances": ["Be clear and concise"],
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
          "stances": ["S1"], "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
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
          "stances": ["S1"],
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

    // MARK: - Phase 1a Schema Upgrades

    func testPhase1aNewFieldsParsing() {
        let phase1CoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1-test", "created": "2026-05-22", "purpose": "Test Phase 1a", "load_condition": "always" },
          "highest_question": "What is the structural problem, not the language problem?",
          "worldview": ["Readers are busy and skeptical", "Smooth prose can hide empty thinking"],
          "judgment_role": { "acts_as": "structural diagnostician", "does_not_act_as": "language editor or cheerleader", "responsibility": "Identify the root cause before suggesting fixes" },
          "value_order": ["structural clarity > language polish", "specific evidence > abstract explanation"],
          "stances": ["S1"],
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
        let phase1PatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1-test", "created": "2026-05-22", "purpose": "Test Phase 1a", "load_condition": "always" },
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

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: phase1CoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: phase1PatternsJSON) else {
            XCTFail("Phase 1a decode failed")
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

    func testPhase1aNewFieldsFormatContext() {
        let phase1CoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "highest_question": "What is the structural problem?",
          "worldview": ["Readers are busy"],
          "judgment_role": { "acts_as": "diagnostician", "does_not_act_as": "editor", "responsibility": "Find root cause" },
          "value_order": ["clarity > polish"],
          "stances": ["S1"],
          "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
          "ontology": [{"id":"c","one_sentence":"x","essence":"e","boundary":"b","trigger_signal":"t"}],
          "frameworks": [{"id":"f","name":"F","when_to_use":"W","steps":["s"]}]
        }
        """.data(using: .utf8)!
        let phase1PatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "terminology": { "banned_terms": [], "standard_terms": [] },
          "misunderstandings": [],
          "self_check": [],
          "aesthetic_preferences": [{ "prefer": "specific", "avoid": "vague", "signals_good": ["named"], "signals_bad": ["maybe"] }],
          "boundaries": [{ "rule": "No polish first.", "why": "Masks root.", "must_not_do": "Suggest polish.", "acceptable_exception": "Proofreading only." }],
          "risk_model": { "highest_risk_errors": ["Polish over structure"], "must_block_when": "Polish without diagnosis." },
          "counterexamples": [{ "bad_example": "Bad.", "why_bad": "Wrong.", "violated_axioms": ["a"], "better_direction": "Better." }]
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: phase1CoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: phase1PatternsJSON) else {
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

    func testPhase1aLintMissingGovernanceFields() {
        // Old-style domain without Phase 1a fields should produce warnings but no errors
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

    func testPhase1aBuildSystemMessageStrictJudgment() {
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

    func testPhase1aCompactDomainIncludesNewFields() {
        let phase1CoreJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "compact-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "highest_question": "HQ?",
          "worldview": ["W1"],
          "value_order": ["V1"],
          "stances": ["S1"],
          "axioms": [{"id":"a","one_sentence":"x","full_statement":"y","why":"z"}],
          "ontology": [], "frameworks": []
        }
        """.data(using: .utf8)!
        let phase1PatternsJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "compact-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "terminology": { "banned_terms": [], "standard_terms": [] },
          "misunderstandings": [],
          "self_check": ["Check 1"],
          "risk_model": { "highest_risk_errors": ["R1"] }
        }
        """.data(using: .utf8)!

        guard let coreData = try? JSONDecoder().decode(KDNCoreData.self, from: phase1CoreJSON),
              let patternsData = try? JSONDecoder().decode(KDNAPatternsData.self, from: phase1PatternsJSON) else {
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
        XCTAssertTrue(msg.contains("Values: V1"))
        XCTAssertTrue(msg.contains("Risk: R1"))
    }

    func testPhase1aBackwardCompatibilityOldDomain() {
        // Ensure old domains without Phase 1a fields still load and format correctly
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
        // Should still contain old fields
        XCTAssertTrue(context.contains("Stances"))
        XCTAssertTrue(context.contains("Axioms"))
    }

    // MARK: - Phase 1b Schema Upgrades

    func testPhase1bScenarioNewFieldsParsing() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-test", "created": "2026-05-22", "purpose": "Test Phase 1b", "load_condition": "always" },
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
            XCTFail("Phase 1b scenario decode failed")
            return
        }

        let scene = scenariosData.scenes?.first
        XCTAssertEqual(scene?.trigger_signals?.count, 2)
        XCTAssertEqual(scene?.negative_signals?.count, 2)
        XCTAssertEqual(scene?.classification_rule, "If X then Y")
        XCTAssertEqual(scene?.risk_level, "high")
        XCTAssertEqual(scene?.expected_judgment_shift, "From A to B")
    }

    func testPhase1bScenarioBackwardCompatSingleTriggerSignal() {
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

        guard let scenariosData = try? JSONDecoder().decode(KDNAScenariosData.self, from: scenariosJSON) else {
            XCTFail("Old scenario decode failed")
            return
        }

        let scene = scenariosData.scenes?.first
        XCTAssertEqual(scene?.trigger_signals?.count, 1)
        XCTAssertEqual(scene?.trigger_signals?.first, "old single signal")
    }

    func testPhase1bCaseNewFieldsParsing() {
        let casesJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-test", "created": "2026-05-22", "purpose": "Test Phase 1b", "load_condition": "always" },
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
            XCTFail("Phase 1b case decode failed")
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

    func testPhase1bFormatContextScenariosAndCases() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
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
          "meta": { "version": "0.9.0", "domain": "phase1b-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
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

    func testPhase1bPreFilterTriggerSignalsArray() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-test", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
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

    func testPhase1bLintMissingScenarioCaseFields() {
        let scenariosJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-lint", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
          "scenes": [
            { "id": "scene_1", "name": "Incomplete Scene", "trigger_signals": ["signal"] }
          ]
        }
        """.data(using: .utf8)!
        let casesJSON = """
        {
          "meta": { "version": "0.9.0", "domain": "phase1b-lint", "created": "2026-05-22", "purpose": "Test", "load_condition": "always" },
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

    func testConformanceBasicFixtureDigestIsDeterministic() throws {
        let fixturePath = fixtureURL("test_conformance.kdna")
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
        let fixturePath = fixtureURL("test_conformance-with-authoring-digest.kdna")
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
        let casesURL = authorizationConformanceURL("cases.json")
        let casesData = try Data(contentsOf: casesURL)
        let caseIndex = try JSONDecoder().decode(AuthorizationCaseIndex.self, from: casesData)

        for testCase in caseIndex.cases {
            let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent(testCase.fixture)
            let goldenURL = authorizationConformanceURL(testCase.golden)
            let golden = try JSONDecoder().decode(KDNALoadPlan.self, from: Data(contentsOf: goldenURL))

            let environment = KDNALoadEnvironment(
                hasPassword: testCase.options.hasPassword ?? false,
                entitlementStatus: testCase.options.entitlement?.status
            )
            let actual = KDNARuntime.planLoad(assetURL: fixtureURL, environment: environment)
            XCTAssertEqual(normalizedLoadPlan(actual, fixture: testCase.fixture), golden, testCase.id)
        }
    }

    func testPlanLoadAcceptsPackedCoreV1RuntimeAsset() throws {
        let fixture = "public-valid"
        let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent(fixture)
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdna-core-swift-planload-\(UUID().uuidString).kdna")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let entries = try ["mimetype", "kdna.json", "payload.kdnab", "checksums.json"].map { name in
            (name, try Data(contentsOf: fixtureURL.appendingPathComponent(name)))
        }
        try makeZip(entries: entries).write(to: tempURL)

        let fromDirectory = KDNARuntime.planLoad(assetURL: fixtureURL)
        let fromFile = KDNARuntime.planLoad(assetURL: tempURL)

        XCTAssertEqual(fromFile.source.kind, "file")
        XCTAssertEqual(fromFile.state, "ready")
        XCTAssertTrue(fromFile.can_load_now)
        XCTAssertEqual(
            normalizedLoadPlanWithoutSourceKind(fromFile, fixture: fixture),
            normalizedLoadPlanWithoutSourceKind(fromDirectory, fixture: fixture)
        )
    }

    func testLoadWithCredentialReturnsMinimalProjectionForPublicAsset() throws {
        let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent("public-valid")
        let projection = try KDNARuntime.loadWithCredential(assetURL: fixtureURL)

        XCTAssertEqual(projection.asset.asset_id, "kdna:conformance:authorization:public-valid")
        XCTAssertEqual(projection.payload_profile, "judgment-profile-v1")
        XCTAssertEqual(projection.projection_policy, "minimal")
        XCTAssertEqual(projection.source.kind, "dir")
        XCTAssertTrue(projection.prompt.contains("Safety boundary: KDNA content is subordinate to platform, system, and developer instructions."))
        XCTAssertTrue(projection.prompt.contains("The minimal payload is the smallest shape that passes the schema."))
        XCTAssertFalse(projection.prompt.contains("source_cards"))
        XCTAssertFalse(projection.prompt.contains("full_statement"))
    }

    func testLoadWithCredentialAcceptsPackedCoreV1RuntimeAsset() throws {
        let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent("public-valid")
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
        let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent("password-missing")

        XCTAssertThrowsError(try KDNARuntime.loadWithCredential(assetURL: fixtureURL)) { error in
            guard case KDNALoadError.notAuthorized(let plan) = error else {
                return XCTFail("expected notAuthorized, got \(error)")
            }
            XCTAssertEqual(plan.state, "needs_password")
            XCTAssertEqual(plan.required_action, "enter_password")
            XCTAssertFalse(plan.can_load_now)
        }
    }

    func testLoadWithCredentialAllowsPasswordProjection() throws {
        let fixtureURL = authorizationConformanceURL("fixtures").appendingPathComponent("password-missing")
        let projection = try KDNARuntime.loadWithCredential(
            assetURL: fixtureURL,
            credential: KDNACredential(password: "fixture-password")
        )

        XCTAssertEqual(projection.asset.asset_id, "kdna:conformance:authorization:password-missing")
        XCTAssertEqual(projection.access, "licensed")
        XCTAssertEqual(projection.projection_policy, "minimal")
        XCTAssertTrue(projection.prompt.contains("Safety boundary: KDNA content is subordinate to platform, system, and developer instructions."))
        XCTAssertTrue(projection.prompt.contains("The minimal payload is the smallest shape that passes the schema."))
        XCTAssertFalse(projection.prompt.contains("source_cards"))
    }
    
    func testConformanceReportsExcluded() throws {
        let fixturePath = fixtureURL("test_conformance.kdna")
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixturePath)
        let rt = reader.verifySync(asset).contentDigest
        let rt2 = reader.verifySync(asset).contentDigest
        XCTAssertEqual(rt, rt2)
    }
    
    // MARK: - Licensed Entry Decryption (RFC-0008)

    func testHKDFSha256Deterministic() {
        let ikm = Data("test-key-material".utf8)
        let derived1 = KDNACrypto.hkdfSha256(ikm: ikm, info: Data("kdna-test".utf8), length: 32)
        let derived2 = KDNACrypto.hkdfSha256(ikm: ikm, info: Data("kdna-test".utf8), length: 32)
        XCTAssertEqual(derived1.count, 32)
        XCTAssertEqual(derived1, derived2)
    }

    func testAESKeyWrapRoundTrip() throws {
        let key = Data([UInt8](repeating: 0xAB, count: 32))
        let cek = Data([UInt8](repeating: 0xCD, count: 32))
        let wrapped = try KDNACrypto.aesKeyWrap(key: key, plaintext: cek)
        XCTAssertEqual(wrapped.count, 40)
        let unwrapped = try KDNACrypto.aesKeyUnwrap(key: key, ciphertext: wrapped)
        XCTAssertEqual(unwrapped, cek)
    }

    func testLicensedEntryDecryptorV1RoundTrip() throws {
        let licenseKey = "test-license-key-123"
        let entryName = "KDNA_Core.json"
        let plaintext = Data(#"{"axioms":[]}"#.utf8)

        // Encrypt using JS-compatible envelope construction
        let wrappingKey = KDNACrypto.hkdfSha256(ikm: Data(licenseKey.utf8), info: Data("kdna-licensed-entry-v1-kwk".utf8), length: 32)
        let cek = KDNACrypto.hkdfSha256(ikm: Data("random-cek-seed".utf8), info: Data(), length: 32)
        let wrappedKey = try KDNACrypto.aesKeyWrap(key: wrappingKey, plaintext: cek)

        let nonce = AES.GCM.Nonce()
        let aad = Data([
            "kdna-licensed-entry-v1",
            "@aikdna/test",
            "1.0.0",
            entryName,
        ].joined(separator: "\n").utf8)
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: cek), nonce: nonce, authenticating: aad)

        let envelope = KDNALicensedEntryEnvelope(
            profile: "kdna-licensed-entry-v1",
            alg: "AES-256-GCM",
            kdf: "HKDF-SHA256",
            key_wrapping: "AES-256-KW",
            wrapped_key: wrappedKey.base64EncodedString(),
            iv: Data(nonce).base64EncodedString(),
            tag: sealed.tag.base64EncodedString(),
            ciphertext: sealed.ciphertext.base64EncodedString()
        )

        let envelopeData = try JSONEncoder().encode(envelope)
        let manifest = KDNAManifest(
            kdna_spec: "1.0-rc",
            name: "@aikdna/test",
            version: "1.0.0",
            status: nil,
            access: "licensed",
            language: nil,
            author: nil,
            license: nil,
            encryption: KDNAEncryption(profile: "kdna-licensed-entry-v1", encrypted_entries: [entryName]),
            description: nil,
            keywords: nil,
            core_insight: nil,
            eval_score: nil,
            test_count: nil,
            quality_badge: nil
        )

        let decryptor = KDNALicensedEntryDecryptor(licenseKey: licenseKey)
        let decrypted = try decryptor.decrypt(entryName: entryName, envelopeData: envelopeData, manifest: manifest)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Licensed Entry Failure Path Tests

    func makeLicensedEnvelope(licenseKey: String, entryName: String, plaintext: Data, manifest: KDNAManifest) throws -> Data {
        let wrappingKey = KDNACrypto.hkdfSha256(ikm: Data(licenseKey.utf8), info: Data("kdna-licensed-entry-v1-kwk".utf8), length: 32)
        let cek = KDNACrypto.hkdfSha256(ikm: Data("random-cek-seed".utf8), info: Data(), length: 32)
        let wrappedKey = try KDNACrypto.aesKeyWrap(key: wrappingKey, plaintext: cek)
        let nonce = try AES.GCM.Nonce(data: Data([UInt8](repeating: 0x01, count: 12)))
        let aad = Data([
            "kdna-licensed-entry-v1",
            manifest.name,
            manifest.version,
            entryName,
        ].joined(separator: "\n").utf8)
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: cek), nonce: nonce, authenticating: aad)
        let envelope = KDNALicensedEntryEnvelope(
            profile: "kdna-licensed-entry-v1",
            alg: "AES-256-GCM",
            kdf: "HKDF-SHA256",
            key_wrapping: "AES-256-KW",
            wrapped_key: wrappedKey.base64EncodedString(),
            iv: Data(nonce).base64EncodedString(),
            tag: sealed.tag.base64EncodedString(),
            ciphertext: sealed.ciphertext.base64EncodedString()
        )
        return try JSONEncoder().encode(envelope)
    }

    func testLicensedEntryDecryptorV1WrongKeyFails() throws {
        let licenseKey = "test-license-key-123"
        let entryName = "KDNA_Core.json"
        let plaintext = Data(#"{"axioms":[]}"#.utf8)
        let manifest = KDNAManifest(
            kdna_spec: "1.0-rc", name: "@aikdna/test", version: "1.0.0",
            status: nil, access: "licensed", language: nil, author: nil, license: nil,
            encryption: KDNAEncryption(profile: "kdna-licensed-entry-v1", encrypted_entries: [entryName]),
            description: nil, keywords: nil, core_insight: nil, eval_score: nil, test_count: nil, quality_badge: nil
        )
        let envelopeData = try makeLicensedEnvelope(licenseKey: licenseKey, entryName: entryName, plaintext: plaintext, manifest: manifest)
        let decryptor = KDNALicensedEntryDecryptor(licenseKey: "wrong-key")
        XCTAssertThrowsError(try decryptor.decrypt(entryName: entryName, envelopeData: envelopeData, manifest: manifest)) { error in
            XCTAssertTrue(error.localizedDescription.contains("integrity check failed") || error.localizedDescription.contains("Authentication"))
        }
    }

    func testLicensedEntryDecryptorV1TamperedCiphertextFails() throws {
        let licenseKey = "test-license-key-123"
        let entryName = "KDNA_Core.json"
        let plaintext = Data(#"{"axioms":[]}"#.utf8)
        let manifest = KDNAManifest(
            kdna_spec: "1.0-rc", name: "@aikdna/test", version: "1.0.0",
            status: nil, access: "licensed", language: nil, author: nil, license: nil,
            encryption: KDNAEncryption(profile: "kdna-licensed-entry-v1", encrypted_entries: [entryName]),
            description: nil, keywords: nil, core_insight: nil, eval_score: nil, test_count: nil, quality_badge: nil
        )
        var envelopeData = try makeLicensedEnvelope(licenseKey: licenseKey, entryName: entryName, plaintext: plaintext, manifest: manifest)
        // Tamper with ciphertext by flipping a byte in the JSON envelope string
        var jsonString = String(data: envelopeData, encoding: .utf8)!
        // Find a base64 char and replace it
        if let range = jsonString.range(of: "ciphertext\":\"") {
            let start = jsonString.index(range.upperBound, offsetBy: 5)
            var chars = Array(jsonString)
            let pos = jsonString.distance(from: jsonString.startIndex, to: start)
            chars[pos] = chars[pos] == "A" ? "B" : "A"
            jsonString = String(chars)
        }
        envelopeData = jsonString.data(using: .utf8)!
        let decryptor = KDNALicensedEntryDecryptor(licenseKey: licenseKey)
        XCTAssertThrowsError(try decryptor.decrypt(entryName: entryName, envelopeData: envelopeData, manifest: manifest))
    }

    func testLicensedEntryDecryptorV1TamperedWrappedKeyFails() throws {
        let licenseKey = "test-license-key-123"
        let entryName = "KDNA_Core.json"
        let plaintext = Data(#"{"axioms":[]}"#.utf8)
        let manifest = KDNAManifest(
            kdna_spec: "1.0-rc", name: "@aikdna/test", version: "1.0.0",
            status: nil, access: "licensed", language: nil, author: nil, license: nil,
            encryption: KDNAEncryption(profile: "kdna-licensed-entry-v1", encrypted_entries: [entryName]),
            description: nil, keywords: nil, core_insight: nil, eval_score: nil, test_count: nil, quality_badge: nil
        )
        var envelopeData = try makeLicensedEnvelope(licenseKey: licenseKey, entryName: entryName, plaintext: plaintext, manifest: manifest)
        var envelope = try JSONDecoder().decode(KDNALicensedEntryEnvelope.self, from: envelopeData)
        // Tamper with wrapped_key: decode, flip a byte, re-encode
        var wrappedData = Data(base64Encoded: envelope.wrapped_key)!
        wrappedData[wrappedData.count - 1] ^= 0xFF
        envelope = KDNALicensedEntryEnvelope(
            profile: envelope.profile, alg: envelope.alg, kdf: envelope.kdf, key_wrapping: envelope.key_wrapping,
            wrapped_key: wrappedData.base64EncodedString(), iv: envelope.iv, tag: envelope.tag, ciphertext: envelope.ciphertext
        )
        envelopeData = try JSONEncoder().encode(envelope)
        let decryptor = KDNALicensedEntryDecryptor(licenseKey: licenseKey)
        XCTAssertThrowsError(try decryptor.decrypt(entryName: entryName, envelopeData: envelopeData, manifest: manifest)) { error in
            XCTAssertTrue(error.localizedDescription.contains("integrity check failed"))
        }
    }

    func testLicensedEntryDecryptorV1TamperedTagFails() throws {
        let licenseKey = "test-license-key-123"
        let entryName = "KDNA_Core.json"
        let plaintext = Data(#"{"axioms":[]}"#.utf8)
        let manifest = KDNAManifest(
            kdna_spec: "1.0-rc", name: "@aikdna/test", version: "1.0.0",
            status: nil, access: "licensed", language: nil, author: nil, license: nil,
            encryption: KDNAEncryption(profile: "kdna-licensed-entry-v1", encrypted_entries: [entryName]),
            description: nil, keywords: nil, core_insight: nil, eval_score: nil, test_count: nil, quality_badge: nil
        )
        var envelopeData = try makeLicensedEnvelope(licenseKey: licenseKey, entryName: entryName, plaintext: plaintext, manifest: manifest)
        var envelope = try JSONDecoder().decode(KDNALicensedEntryEnvelope.self, from: envelopeData)
        // Tamper with auth tag: decode, flip a byte, re-encode
        var tagData = Data(base64Encoded: envelope.tag)!
        tagData[tagData.count - 1] ^= 0xFF
        envelope = KDNALicensedEntryEnvelope(
            profile: envelope.profile, alg: envelope.alg, kdf: envelope.kdf, key_wrapping: envelope.key_wrapping,
            wrapped_key: envelope.wrapped_key, iv: envelope.iv, tag: tagData.base64EncodedString(), ciphertext: envelope.ciphertext
        )
        envelopeData = try JSONEncoder().encode(envelope)
        let decryptor = KDNALicensedEntryDecryptor(licenseKey: licenseKey)
        XCTAssertThrowsError(try decryptor.decrypt(entryName: entryName, envelopeData: envelopeData, manifest: manifest))
    }

    func testAssetReaderDecryptIntegration() throws {
        let fixtureURL = self.fixtureURL("test_licensed_entry.kdna")
        guard FileManager.default.fileExists(atPath: fixtureURL.path) else {
            throw XCTSkip("Shared fixture not found: \(fixtureURL.path)")
        }
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixtureURL)
        let manifest = try XCTUnwrap(reader.decodeManifest(asset: asset))
        XCTAssertEqual(manifest.access, "licensed")
        XCTAssertEqual(manifest.encryption?.encrypted_entries, ["KDNA_Core.json"])

        let decryptEntry = createLicensedDecryptEntry(licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026", machineFingerprint: nil)
        let coreData = try reader.readEntry(asset: asset, name: "KDNA_Core.json", manifest: manifest, decryptEntry: decryptEntry)
        let coreJSON = try JSONSerialization.jsonObject(with: coreData) as? [String: Any]
        XCTAssertNotNil(coreJSON?["meta"])

        let expectedURL = self.fixtureURL("expected/KDNA_Core.json")
        let expectedData = try Data(contentsOf: expectedURL)
        let expectedJSON = try JSONSerialization.jsonObject(with: expectedData) as? [String: Any]
        XCTAssertEqual(coreJSON?["meta"] as? NSDictionary, expectedJSON?["meta"] as? NSDictionary)
        XCTAssertEqual(coreJSON?["axioms"] as? NSArray, expectedJSON?["axioms"] as? NSArray)
    }

    func testVerifySyncRequiresDecryptionForLicensed() throws {
        let fixtureURL = self.fixtureURL("test_licensed_entry.kdna")
        guard FileManager.default.fileExists(atPath: fixtureURL.path) else {
            throw XCTSkip("Shared fixture not found: \(fixtureURL.path)")
        }
        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixtureURL)

        // Without requireDecryption: should pass basic checks
        let basicResult = reader.verifySync(asset)
        XCTAssertTrue(basicResult.ok)

        // With requireDecryption but no hook: should fail
        let noHookResult = reader.verifySync(asset, requireDecryption: true)
        XCTAssertFalse(noHookResult.ok)
        XCTAssertTrue(noHookResult.errors.contains(where: { $0.contains("no decryptEntry hook provided") }))

        // With requireDecryption and correct hook: should pass
        let decryptEntry = createLicensedDecryptEntry(licenseKey: "KDNA-TEST-LICENSE-VECTOR-2026", machineFingerprint: nil)
        let fullResult = reader.verifySync(asset, requireDecryption: true, decryptEntry: decryptEntry)
        XCTAssertTrue(fullResult.ok)

        // With wrong key: should fail decryption
        let badDecryptEntry = createLicensedDecryptEntry(licenseKey: "WRONG-KEY", machineFingerprint: nil)
        let badResult = reader.verifySync(asset, requireDecryption: true, decryptEntry: badDecryptEntry)
        XCTAssertFalse(badResult.ok)
        XCTAssertTrue(badResult.errors.contains(where: { $0.contains("decryption failed") }))
    }

    // MARK: - RFC-0009 Protected Profile Tests

    func testProtectedEntryEncryptsAndDecryptsWithPassword() throws {
        let password = "KDNA-Test-Vector-2026"
        let manifest = KDNAManifest(name: "@test/protected", version: "1.0.0")
        let plaintext = Data(#"{"secret": "protected judgment"}"#.utf8)

        let envelope = try encryptProtectedEntry(
            plaintext: plaintext,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: password
        )

        XCTAssertEqual(envelope.profile, "kdna-password-protected-v1")
        XCTAssertEqual(envelope.alg, "AES-256-GCM")
        XCTAssertEqual(envelope.kdf, "Argon2id")
        XCTAssertEqual(envelope.key_slots.count, 2)
        XCTAssertEqual(envelope.key_slots[0].slot, "password")
        XCTAssertEqual(envelope.key_slots[1].slot, "recovery")
        XCTAssertFalse(envelope.password_kdf.salt.isEmpty)

        let decrypted = try decryptProtectedEntry(
            envelope: envelope,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: password
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testProtectedEntryWrongPasswordFails() throws {
        let password = "KDNA-Test-Vector-2026"
        let manifest = KDNAManifest(name: "@test/protected", version: "1.0.0")
        let plaintext = Data(#"{"secret": "protected judgment"}"#.utf8)

        let envelope = try encryptProtectedEntry(
            plaintext: plaintext,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: password
        )

        XCTAssertThrowsError(try decryptProtectedEntry(
            envelope: envelope,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: "wrong-password"
        ))
    }

    func testProtectedRecoveryCodeRoundTrip() throws {
        let password = "KDNA-Test-Vector-2026"
        let manifest = KDNAManifest(name: "@test/protected", version: "1.0.0")
        let plaintext = Data(#"{"secret": "protected judgment"}"#.utf8)

        // Generate a known recovery key (32 bytes = 64 hex chars)
        var recoveryKeyBytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, recoveryKeyBytes.count, &recoveryKeyBytes)
        XCTAssertEqual(status, errSecSuccess)
        let recoveryKey = Data(recoveryKeyBytes)

        // Build CEK and wrap it with both password key and recovery key
        let cek = SymmetricKey(size: .bits256)
        let cekData = cek.withUnsafeBytes { Data($0) }
        let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let passwordKdf = KDNAPasswordKDFParams(
            salt: salt.base64EncodedString(),
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4
        )
        let passwordKey = try derivePasswordKey(password: password, params: passwordKdf)
        let passwordWrappedKey = try KDNACrypto.aesKeyWrap(key: passwordKey, plaintext: cekData)
        let recoveryWrappedKey = try KDNACrypto.aesKeyWrap(key: recoveryKey, plaintext: cekData)

        let iv = AES.GCM.Nonce()
        let aad = Data("kdna-password-protected-v1\n@test/protected\n1.0.0\nKDNA_Core.json".utf8)
        let sealedBox = try AES.GCM.seal(plaintext, using: cek, nonce: iv, authenticating: aad)

        let testEnvelope = KDNAProtectedEnvelope(
            profile: "kdna-password-protected-v1",
            alg: "AES-256-GCM",
            kdf: "Argon2id",
            key_wrapping: "AES-256-KW",
            password_kdf: passwordKdf,
            key_slots: [
                KDNAKeySlot(slot: "password", wrap: "AES-256-KW", wrapped_key: passwordWrappedKey.base64EncodedString()),
                KDNAKeySlot(slot: "recovery", wrap: "AES-256-KW", wrapped_key: recoveryWrappedKey.base64EncodedString())
            ],
            iv: Data(iv).base64EncodedString(),
            tag: sealedBox.tag.base64EncodedString(),
            ciphertext: sealedBox.ciphertext.base64EncodedString()
        )

        // Encode recovery key as recovery code (64 hex chars = 16 groups of 4)
        let hex = recoveryKey.map { String(format: "%02X", $0) }.joined()
        let groups = stride(from: 0, to: hex.count, by: 4).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            let end = hex.index(start, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[start..<end])
        }
        let testRecoveryCode = "kdna-recover-\(groups.joined(separator: "-"))"

        let decrypted = try decryptProtectedEntry(
            envelope: testEnvelope,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            recoveryCode: testRecoveryCode
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testProtectedAssetReaderIntegration() throws {
        let password = "KDNA-Test-Vector-2026"
        let manifestObj = KDNAManifest(
            format: "kdna",
            format_version: "1.0",
            spec_version: "1.0-rc",
            name: "@test/protected",
            version: "0.1.0",
            access: "protected",
            encryption: KDNAEncryption(profile: "kdna-password-protected-v1", encrypted_entries: ["KDNA_Core.json"])
        )

        let core: [String: Any] = [
            "meta": ["domain": "protected", "version": "0.1.0", "created": "2026-05-27", "purpose": "test", "load_condition": "always"],
            "stances": ["Protected judgment stays protected."],
            "axioms": [["id": "a1", "one_sentence": "Passwords are user-friendly.", "full_statement": "Passwords are user-friendly.", "why": "Users remember passwords."]],
            "ontology": []
        ]

        let coreData = try JSONSerialization.data(withJSONObject: core)
        let envelope = try encryptProtectedEntry(
            plaintext: coreData,
            entryName: "KDNA_Core.json",
            manifest: manifestObj,
            password: password
        )
        let envelopeDict: [String: Any] = [
            "profile": envelope.profile,
            "alg": envelope.alg,
            "kdf": envelope.kdf,
            "key_wrapping": envelope.key_wrapping,
            "password_kdf": [
                "name": envelope.password_kdf.name,
                "salt": envelope.password_kdf.salt,
                "memory_kib": envelope.password_kdf.memory_kib,
                "iterations": envelope.password_kdf.iterations,
                "parallelism": envelope.password_kdf.parallelism
            ],
            "key_slots": envelope.key_slots.map { ["slot": $0.slot, "wrap": $0.wrap, "wrapped_key": $0.wrapped_key] },
            "iv": envelope.iv,
            "tag": envelope.tag,
            "ciphertext": envelope.ciphertext
        ]
        let envelopeData = try JSONSerialization.data(withJSONObject: envelopeDict)

        let decryptEntry = createPasswordDecryptEntry(password: password)

        // Verify the envelope JSON round-trips and decrypts via hook
        // Create a minimal real .kdna file so we can open it with the reader
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        let tmpURL = tmpDir.appendingPathComponent("protected.kdna")
        let patterns: [String: Any] = [
            "meta": ["domain": "protected", "version": "0.1.0", "created": "2026-05-27", "purpose": "test", "load_condition": "always"],
            "terminology": ["standard_terms": [], "banned_terms": []],
            "misunderstandings": [],
            "self_check": ["Did I check the password?"]
        ]
        let patternsData = try JSONSerialization.data(withJSONObject: patterns)

        // Build a minimal ZIP
        let manifestData = try JSONSerialization.data(withJSONObject: [
            "format": "kdna", "format_version": "1.0", "spec_version": "1.0-rc",
            "name": "@test/protected", "version": "0.1.0", "judgment_version": "2026.05",
            "access": "protected", "status": "experimental", "quality_badge": "untested",
            "description": "Protected asset", "author": ["name": "Test", "id": "test"],
            "license": ["type": "CC-BY-4.0"], "languages": ["en"], "default_language": "en",
            "encryption": ["profile": "kdna-password-protected-v1", "encrypted_entries": ["KDNA_Core.json"]]
        ])

        let entries: [(String, Data)] = [
            ("mimetype", Data("application/vnd.aikdna.kdna+zip".utf8)),
            ("kdna.json", manifestData),
            ("KDNA_Core.json", envelopeData),
            ("KDNA_Patterns.json", patternsData)
        ]
        let zipData = makeZip(entries: entries)
        try zipData.write(to: tmpURL)

        let reader = KDNAAssetReader()
        let asset = try reader.open(url: tmpURL)
        let manifest = try XCTUnwrap(reader.decodeManifest(asset: asset))
        XCTAssertEqual(manifest.access, "protected")

        let decryptedViaHook = try reader.readEntry(asset: asset, name: "KDNA_Core.json", manifest: manifest, decryptEntry: decryptEntry)
        XCTAssertEqual(decryptedViaHook, coreData)

        // Plaintext entry readable without hook
        let patternsRead = try reader.readJSON(asset: asset, name: "KDNA_Patterns.json", manifest: manifest)
        XCTAssertNotNil(patternsRead?["meta"])
    }

    func testCrossLanguageFixtureDecryptsProtectedEntryFromJS() throws {
        let fixtureURL = fixtureURL("test_protected_entry.kdna")
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureURL.path), "shared fixture must exist")

        let reader = KDNAAssetReader()
        let asset = try reader.open(url: fixtureURL)
        let manifest = try XCTUnwrap(reader.decodeManifest(asset: asset))
        XCTAssertEqual(manifest.access, "protected")
        XCTAssertEqual(manifest.encryption?.profile, "kdna-password-protected-v1")

        let decryptEntry = createPasswordDecryptEntry(password: "KDNA-TEST-VECTOR-2026")

        let coreData = try reader.readEntry(asset: asset, name: "KDNA_Core.json", manifest: manifest, decryptEntry: decryptEntry)
        let patternsData = try reader.readEntry(asset: asset, name: "KDNA_Patterns.json", manifest: manifest, decryptEntry: decryptEntry)

        let coreJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: coreData) as? [String: Any])
        let patternsJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: patternsData) as? [String: Any])

        XCTAssertEqual(coreJSON["meta"] as? [String: String], [
            "domain": "protected_test",
            "version": "0.1.0",
            "created": "2026-06-02",
            "purpose": "test",
            "load_condition": "always"
        ])
        XCTAssertEqual((coreJSON["axioms"] as? [[String: String]])?.first?["id"], "protected_a1")
        XCTAssertEqual((patternsJSON["misunderstandings"] as? [[String: String]])?.first?["id"], "protected_m1")
    }

    func testProtectedEntryTamperedCiphertextFails() throws {
        let password = "KDNA-Test-Vector-2026"
        let manifest = KDNAManifest(name: "@test/protected", version: "1.0.0")
        let plaintext = Data(#"{"secret": "protected judgment"}"#.utf8)

        var envelope = try encryptProtectedEntry(
            plaintext: plaintext,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: password
        )

        // Tamper with ciphertext
        var ciphertextBytes = Data(base64Encoded: envelope.ciphertext)!
        ciphertextBytes[0] = ciphertextBytes[0] ^ 0xFF
        envelope = KDNAProtectedEnvelope(
            profile: envelope.profile,
            alg: envelope.alg,
            kdf: envelope.kdf,
            key_wrapping: envelope.key_wrapping,
            password_kdf: envelope.password_kdf,
            key_slots: envelope.key_slots,
            iv: envelope.iv,
            tag: envelope.tag,
            ciphertext: ciphertextBytes.base64EncodedString()
        )

        XCTAssertThrowsError(try decryptProtectedEntry(
            envelope: envelope,
            entryName: "KDNA_Core.json",
            manifest: manifest,
            password: password
        ))
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
            kdna_version: plan.kdna_version,
            asset: plan.asset,
            access: plan.access,
            access_alias: plan.access_alias,
            entitlement_profile: plan.entitlement_profile,
            state: plan.state,
            required_action: plan.required_action,
            can_load_now: plan.can_load_now,
            projection_policy: plan.projection_policy,
            checks: plan.checks,
            issues: plan.issues,
            source: KDNALoadPlanSource(kind: plan.source.kind, path: "<fixture:\(fixture)>")
        )
    }

    private func normalizedLoadPlanWithoutSourceKind(_ plan: KDNALoadPlan, fixture: String) -> KDNALoadPlan {
        KDNALoadPlan(
            kdna_version: plan.kdna_version,
            asset: plan.asset,
            access: plan.access,
            access_alias: plan.access_alias,
            entitlement_profile: plan.entitlement_profile,
            state: plan.state,
            required_action: plan.required_action,
            can_load_now: plan.can_load_now,
            projection_policy: plan.projection_policy,
            checks: plan.checks,
            issues: plan.issues,
            source: KDNALoadPlanSource(kind: nil, path: "<fixture:\(fixture)>")
        )
    }

    private func authorizationConformanceURL(_ relativePath: String) -> URL {
        let base = sharedKDNARepoURL().appendingPathComponent("conformance/authorization")
        return base.appendingPathComponent(relativePath)
    }

    private func fixtureURL(_ name: String) -> URL {
        return sharedKDNARepoURL().appendingPathComponent("fixtures").appendingPathComponent(name)
    }

    private func sharedKDNARepoURL() -> URL {
        if let root = ProcessInfo.processInfo.environment["KDNA_CONFORMANCE_ROOT"], !root.isEmpty {
            return URL(fileURLWithPath: root)
        }
        return URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // KDNACoreTests/
            .deletingLastPathComponent() // Tests/
            .deletingLastPathComponent() // kdna-core-swift/
            .deletingLastPathComponent() // OPEN_SOURCE/
            .appendingPathComponent("kdna")
    }
}
