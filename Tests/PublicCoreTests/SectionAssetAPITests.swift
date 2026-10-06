import XCTest
import Foundation
@testable import KDNACore

// The public asset-hung surface (design note §4/§6): open → admit →
// authority → read, against the committed synthetic fixture. This is the
// surface the gvjl product consumes; the assertions mirror the internal
// whole-read acceptance.
final class SectionAssetAPITests: XCTestCase {
    func testWholeReadThroughPublicSurface() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let asset = try KDNASectionAsset.open(bytes: bytes, expectedSHA256: "sha256:5f87e64fbc57637051d3bb692dc5e168e3e4328b8073d06bbfd9c1b0eb16078e")
        XCTAssertEqual(asset.fileSHA256.hasPrefix("sha256:"), true)
        XCTAssertEqual(asset.manifest["asset_id"].text, "asset:course-craft-standards")
        var authorized = 0
        let authority = try asset.createReadAuthority { _ in authorized += 1; return true }
        let admitted = try asset.admitWholeReadRequest(requestId: "public-api-1", budgetBytes: 1048576)
        let outcome = await asset.readWhole(admitted, authority)
        XCTAssertEqual(outcome.envelope["status"].text, "accepted")
        XCTAssertEqual(authorized, 1)
        let view = try XCTUnwrap(outcome.snapshot).inspect()
        XCTAssertEqual(view["verification"]["ir_digest"]["digest"].text, "sha256:aa3f961aa78506f9d804b28c2abb52dd29d9a26a802ab825f3608474f6ced747")
    }
    func testDeniedCallbackAndExpectedDigest() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let asset = try KDNASectionAsset.open(bytes: bytes)
        let authority = try asset.createReadAuthority { _ in false }
        let admitted = try asset.admitWholeReadRequest(requestId: "public-api-2", budgetBytes: 1048576)
        let outcome = await asset.readWhole(admitted, authority)
        XCTAssertEqual(outcome.envelope["status"].text, "rejected")
        XCTAssertEqual(outcome.envelope["reason"].text, "SECTION_PERMISSION_DENIED")
        XCTAssertNil(outcome.snapshot)
        // Truthy non-Bool (the Node strict `!== true` case) cannot arise here:
        // the callback is Bool?, so only nil/false deny.
        XCTAssertThrowsError(try KDNASectionAsset.open(bytes: bytes, expectedSHA256: "sha256:" + String(repeating: "0", count: 64))) { error in
            XCTAssertEqual((error as? KDNASectionError)?.code, "READ_INPUT_INVALID")
        }
    }
}
