import XCTest
import CryptoKit
@testable import KDNACore

final class LoaderCompatibilityTests: XCTestCase {
    private struct VectorFixture: Decodable {
        let canonical_commit: String
        let loader_version: String
        let vectors: [Vector]
    }

    private struct Vector: Codable, Equatable {
        let required: String
        let valid: Bool
        let comparison: Int?
        let compatible: Bool?
    }

    private struct NodeResult: Decodable {
        let loader_version: String
        let vectors: [Vector]
    }

    func testStrictVectorsMatchCurrentSwiftLoader() throws {
        let fixture = try vectorFixture()
        XCTAssertEqual(fixture.canonical_commit, KDNACanonicalSchemas.canonicalCommit)
        XCTAssertEqual(fixture.loader_version, KDNALoaderCompatibility.currentVersion)

        for vector in fixture.vectors {
            XCTAssertEqual(
                KDNALoaderCompatibility.parse(vector.required) != nil,
                vector.valid,
                vector.required
            )
            if let expected = vector.comparison {
                XCTAssertEqual(
                    try KDNALoaderCompatibility.compare(
                        vector.required,
                        KDNALoaderCompatibility.currentVersion
                    ),
                    expected,
                    vector.required
                )
            } else {
                XCTAssertThrowsError(
                    try KDNALoaderCompatibility.compare(
                        vector.required,
                        KDNALoaderCompatibility.currentVersion
                    )
                )
            }
            XCTAssertEqual(
                KDNALoaderCompatibility.assess(manifest: manifest(vector.required))
                    .loaderCompatible,
                vector.compatible,
                vector.required
            )
        }

        let prefixed = ["v", KDNALoaderCompatibility.currentVersion].joined()
        XCTAssertNil(KDNALoaderCompatibility.parse(prefixed))
    }

    func testPinnedNodeAndSwiftExecuteTheSameVectors() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let root = environment["KDNA_CONFORMANCE_ROOT"],
              !root.isEmpty else { return }
        let nodePath = try XCTUnwrap(
            environment["NODE"],
            "NODE must name the controlled Node executable when KDNA_CONFORMANCE_ROOT is enabled"
        )
        guard (nodePath as NSString).isAbsolutePath else {
            XCTFail("NODE must be an absolute path")
            return
        }
        var nodeIsDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: nodePath, isDirectory: &nodeIsDirectory),
              !nodeIsDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: nodePath) else {
            XCTFail("NODE must name an existing executable file")
            return
        }
        let nodeExecutableURL = URL(fileURLWithPath: nodePath)
        let fixtureURL = try vectorFixtureURL()
        let moduleURL = URL(fileURLWithPath: root, isDirectory: true)
            .appendingPathComponent("packages/kdna-core/src/loader-compatibility.js")
        let moduleData = try Data(contentsOf: moduleURL)
        guard sha256Hex(moduleData) == "6bc0a34ebcada8181bde391eae3e60a39751dda7e6aca423babad0e9846aac9d" else {
            XCTFail("Node loader compatibility module does not match the fixed Core authority")
            return
        }
        let script = #"""
        const fs = require('fs');
        const fixture = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
        const loader = require(process.argv[2]);
        const vectors = fixture.vectors.map(({ required }) => {
          const valid = loader.parseLoaderVersion(required) !== null;
          return {
            required,
            valid,
            comparison: valid
              ? loader.compareLoaderVersions(required, loader.KDNA_LOADER_VERSION)
              : null,
            compatible: valid
              ? loader.assessLoaderCompatibility({ compatibility: { min_loader_version: required } })
                  .loader_compatible
              : null,
          };
        });
        process.stdout.write(JSON.stringify({
          loader_version: loader.KDNA_LOADER_VERSION,
          vectors,
        }));
        """#
        let process = Process()
        let standardOutput = Pipe()
        let standardError = Pipe()
        process.executableURL = nodeExecutableURL
        process.arguments = ["-e", script, fixtureURL.path, moduleURL.path]
        process.environment = [:]
        process.standardOutput = standardOutput
        process.standardError = standardError
        try process.run()
        process.waitUntilExit()
        let output = standardOutput.fileHandleForReading.readDataToEndOfFile()
        let error = standardError.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(
            process.terminationStatus,
            0,
            String(data: error, encoding: .utf8) ?? "Node vector execution failed"
        )
        let node = try JSONDecoder().decode(NodeResult.self, from: output)
        let fixture = try vectorFixture()
        XCTAssertEqual(node.loader_version, KDNALoaderCompatibility.currentVersion)
        XCTAssertEqual(node.vectors, fixture.vectors)
    }

    func testVerifyPlanAndLoadEnforceCompatibilityBeforeProjection() throws {
        let fixture = try vectorFixture()
        let reader = KDNAAssetReader()

        for vector in fixture.vectors {
            let bytes = try asset(requiredVersion: vector.required)
            let asset = try reader.open(data: bytes, path: "loader-compatibility.kdna")
            let verification = reader.verifySync(asset)
            let plan = KDNALoadPlanCore.planLoad(assetData: bytes)

            if vector.compatible == true {
                XCTAssertTrue(verification.ok, vector.required)
                XCTAssertTrue(plan.checks.overall_valid, vector.required)
                XCTAssertTrue(plan.can_load_now, vector.required)
                XCTAssertNoThrow(try KDNARuntime.load(assetData: bytes), vector.required)
            } else if vector.valid {
                XCTAssertFalse(verification.ok, vector.required)
                XCTAssertTrue(verification.errors.contains {
                    $0.hasPrefix("KDNA_LOADER_VERSION_UNSUPPORTED:")
                })
                XCTAssertTrue(plan.checks.overall_valid, vector.required)
                XCTAssertEqual(plan.state, "invalid")
                XCTAssertEqual(plan.required_action, "block")
                XCTAssertFalse(plan.can_load_now)
                XCTAssertEqual(plan.issues.map(\.code), ["KDNA_LOADER_VERSION_UNSUPPORTED"])
                XCTAssertThrowsError(try KDNARuntime.load(assetData: bytes)) { error in
                    guard case KDNALoadError.notAuthorized(let rejected) = error else {
                        return XCTFail("expected a blocked LoadPlan, got \(error)")
                    }
                    XCTAssertEqual(
                        rejected.issues.map(\.code),
                        ["KDNA_LOADER_VERSION_UNSUPPORTED"]
                    )
                }
            } else {
                XCTAssertFalse(verification.ok, vector.required)
                XCTAssertFalse(verification.errors.contains {
                    $0.hasPrefix("KDNA_LOADER_VERSION_UNSUPPORTED:")
                })
                XCTAssertFalse(plan.checks.schema_valid, vector.required)
                XCTAssertFalse(plan.checks.overall_valid, vector.required)
                XCTAssertTrue(plan.issues.contains { $0.code == "KDNA_FORMAT_INVALID" })
                XCTAssertFalse(plan.issues.contains {
                    $0.code == "KDNA_LOADER_VERSION_UNSUPPORTED"
                })
            }
        }
    }

    private func vectorFixture() throws -> VectorFixture {
        try JSONDecoder().decode(
            VectorFixture.self,
            from: Data(contentsOf: vectorFixtureURL())
        )
    }

    private func vectorFixtureURL() throws -> URL {
        try XCTUnwrap(Bundle.module.url(
            forResource: "loader-compatibility-vectors",
            withExtension: "json"
        ))
    }

    private func manifest(_ minimumVersion: String) -> [String: Any] {
        [
            "compatibility": ["min_loader_version": minimumVersion]
        ]
    }

    private func asset(requiredVersion: String) throws -> Data {
        let manifestData = try JSONSerialization.data(withJSONObject: [
            "format_version": "0.1.0",
            "asset_id": "kdna:test:loader-compatibility",
            "asset_uid": "urn:uuid:00190000-0000-4000-8000-000000000019",
            "asset_type": "fixture",
            "title": "Loader Compatibility Fixture",
            "version": "1.0.0",
            "judgment_version": "1.0.0",
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
            "compatibility": [
                "min_loader_version": requiredVersion,
                "profile": "kdna.payload.judgment",
                "profile_version": "0.1.0",
            ],
            "access": "public",
            "payload": ["path": "payload.kdnab", "encoding": "cbor", "encrypted": false],
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        let payloadData = try KDNACBOR.encode([
            "profile": "kdna.payload.judgment",
            "profile_version": "0.1.0",
            "core": [
                "highest_question": "Can this loader safely consume the asset?",
                "axioms": [
                    "Reject assets that require a newer loader than the current implementation."
                ] as [Any],
            ] as [String: Any],
        ] as [String: Any])
        let checksumsData = try JSONSerialization.data(withJSONObject: [
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
            ("checksums.json", checksumsData),
            ("kdna.json", manifestData),
            ("payload.kdnab", payloadData),
        ])
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = [Data]()
        var centralParts = [Data]()
        var offset: UInt32 = 0
        func u16(_ number: UInt16) -> Data {
            var value = number
            return Data(bytes: &value, count: 2)
        }
        func u32(_ number: UInt32) -> Data {
            var value = number
            return Data(bytes: &value, count: 4)
        }
        for (name, data) in entries {
            let nameData = Data(name.utf8)
            var local = Data()
            local.append(u32(0x04034b50)); local.append(u16(20)); local.append(u16(0))
            local.append(u16(0)); local.append(u16(0)); local.append(u16(0)); local.append(u32(0))
            local.append(u32(UInt32(data.count))); local.append(u32(UInt32(data.count)))
            local.append(u16(UInt16(nameData.count))); local.append(u16(0))
            local.append(nameData); local.append(data); localParts.append(local)
            var central = Data()
            central.append(u32(0x02014b50)); central.append(u16(20)); central.append(u16(20))
            central.append(u16(0)); central.append(u16(0)); central.append(u16(0)); central.append(u16(0))
            central.append(u32(0)); central.append(u32(UInt32(data.count)))
            central.append(u32(UInt32(data.count))); central.append(u16(UInt16(nameData.count)))
            central.append(u16(0)); central.append(u16(0)); central.append(u16(0)); central.append(u16(0))
            central.append(u32(0)); central.append(u32(offset)); central.append(nameData)
            centralParts.append(central); offset += UInt32(local.count)
        }
        let local = localParts.reduce(Data(), +)
        let central = centralParts.reduce(Data(), +)
        var end = Data()
        end.append(u32(0x06054b50)); end.append(u16(0)); end.append(u16(0))
        end.append(u16(UInt16(entries.count))); end.append(u16(UInt16(entries.count)))
        end.append(u32(UInt32(central.count))); end.append(u32(UInt32(local.count)))
        end.append(u16(0))
        return local + central + end
    }
}
