import XCTest
import Foundation
@testable import KDNACore

// Synthetic manifest fixtures only (schema-satisfier generated base plus
// named mutations and a seeded text fuzz). Every row records the released
// validator's verdict: @aikdna/kdna-core@0.36.0 strict.parseJson +
// validate('Manifest06Candidate'), classified through the sections-node
// catch-all. Regeneration method: see the fixture's authority/note fields.
final class SectionManifestTests: XCTestCase {
    func oracle() throws -> J {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "manifest-06-oracles", withExtension: "json", subdirectory: "Fixtures"))
        return try KDNAJSON.parse(Data(contentsOf: url))
    }
    func verdict(_ bytes: [UInt8]) -> String {
        do { _ = try SectionManifest.load(bytes); return "accepted" }
        catch let failure as PublicFailure { return failure.code }
        catch { return "UNEXPECTED:\(error)" }
    }

    func testReleasedManifestOracleRows() throws {
        let fixture = try oracle(), rows = fixture["rows"].list
        XCTAssertGreaterThan(rows.count, 90)
        for row in rows {
            XCTAssertEqual(verdict(Array(row["json"].text.utf8)), row["expected"].text, row["name"].text)
        }
    }

    func testManifestViewProjections() throws {
        let fixture = try oracle()
        let base = try XCTUnwrap(fixture["rows"].list.first { $0["name"].text == fixture["base"].text })
        let manifest = try SectionManifest.load(Array(base["json"].text.utf8))
        XCTAssertEqual(SectionManifest.assetIdentity(manifest).assetId, "asset-1")
        XCTAssertEqual(SectionManifest.assetIdentity(manifest).assetVersion, "0.1.0")
        XCTAssertEqual(SectionManifest.assetIdentity(manifest).judgmentVersion, "0.1.0")
        XCTAssertEqual(SectionManifest.runtimeMandatoryEntries(manifest), ["kdna.json"])
        XCTAssertFalse(SectionManifest.protectionDeclared(manifest))
        XCTAssertEqual(SectionManifest.declaredContentDigests(manifest), [])
        let tables = SectionManifest.payloadTables(manifest)
        XCTAssertEqual(tables.count, 3)
        XCTAssertEqual(tables[1]["member"].text, "sections/pack-1.kdnab")
        XCTAssertEqual(SectionManifest.representationMetadata(manifest)["contract"].text, "kdna.canonical-ir/0.6.1")
    }

    func testProtectionMarkersAreObservable() throws {
        let fixture = try oracle()
        let encrypted = try XCTUnwrap(fixture["rows"].list.first { $0["name"].text == "encrypted-with-encryption" })
        let manifest = try SectionManifest.load(Array(encrypted["json"].text.utf8))
        XCTAssertTrue(SectionManifest.protectionDeclared(manifest))
    }

    func testContractResourcePinFailsClosed() throws {
        let contract = try SectionManifest.loadedContract.get()
        XCTAssertEqual(contract["module"]["versionTuple"]["container"].text, "0.6.0")
        XCTAssertEqual(contract["types"].fields.count, 483)
    }
}
