import XCTest
import Foundation
@testable import KDNACore

final class ZReadScenarioTests: XCTestCase {
    private func merge(_ original: KDNAValue, _ extra: KDNAValue) -> KDNAValue {
        var fields = original.fields
        for (key,value) in extra.fields { fields[key] = value }
        return .object(fields)
    }
    private func outcome(_ result: KDNAValue) -> String {
        if result["envelope"] == .null { return result["channel"].text }
        return result["envelope"]["status"] == "ready" ? "ready" : result["envelope"]["diagnostics"].list.first?["code"].text ?? ""
    }
    private func normalize(_ value: KDNAValue) throws -> String {
        String(decoding: try KDNAJSON.canonical(value), as: UTF8.self)
            .replacingOccurrences(of: "snapshot:[0-9a-f-]{36}", with: "snapshot:00000000-0000-0000-0000-000000000000", options: .regularExpression)
    }
    func testFourModesClosureAndHostLifecycle() async throws {
        let casesURL = try XCTUnwrap(Bundle.module.url(forResource: "read-scenarios", withExtension: "json", subdirectory: "Fixtures"))
        let scenarios = try KDNAJSON.parse(Data(contentsOf: casesURL)).list
        let expectedURL = try XCTUnwrap(Bundle.module.url(forResource: "current-scenario-node", withExtension: "jsonl", subdirectory: "Fixtures"))
        let expected = try String(contentsOf: expectedURL, encoding: .utf8).split(separator: "\n").map { try KDNAJSON.parse(Data($0.utf8)) }
        let comparison = ProcessInfo.processInfo.environment["KDNA_SCENARIO_OUTPUT"] != nil
        var results: [KDNAValue] = []
        for scenario in scenarios {
            let name = scenario["file"].text
            let file = try XCTUnwrap(Bundle.module.url(forResource: String(name.dropLast(5)), withExtension: "kdna", subdirectory: "Fixtures"))
            let snapshot = try XCTUnwrap(KDNACore.admitFile(file).snapshot)
            var step: KDNAValue = [:], calls = 0, lastHandle: KDNAValue = nil, lastBudget = 0
            var prior: [String:KDNAValue] = [:]
            let host = KDNATrustedHostReadProvider(observe: { request,snapshot in
                calls += 1
                let view = snapshot.inspect()
                let dropped = calls % 2 == 0 && step.has("second_drop_roles") ? step["second_drop_roles"].list : step["drop_roles"].list
                var scope = view["ir"]["nodes"].list.filter { !dropped.contains($0["role"]) }.map { $0["id"] }
                if step["mandatory_only"].boolean {
                    scope = view["ir"]["mandatory_closures"].list.first { $0["selection"]["judgment_id"] == "j:0" }?["node_ids"].list ?? []
                }
                let base: KDNAValue = ["host_id":"host:scenario","host_epoch":"epoch:scenario","decision_id":"decision:scenario","request_id":request["request_id"],"snapshot_id":view["snapshot_id"],"A":view["digests"]["A"]["observed"],"C":view["digests"]["C"]["observed"],"scope":.array(scope),"issued_at":900,"expires_at":2000,"decision":"allow","policy_id":"policy:scenario","current_ms":1000]
                return self.merge(self.merge(base,step["host"]),calls % 2 == 0 ? step["second"] : [:])
            }, deliver: { result in
                if let handle = result["envelope"]["content"]["expansion_handles"].list.first { lastHandle = handle }
                return result["channel"] != "transport_failure" && step["delivery"] != false
            })
            for candidate in scenario["steps"].list {
                step = candidate
                calls = 0
                let mode = step.has("mode") ? step["mode"].text : "exact_selection"
                let selection = merge(["asset_id":"asset:bytes","asset_version":"1.0.0","judgment_id":"j:0"],step["selection_change"])
                let budget: KDNAValue = step["budget"].numeric.isFinite ? step["budget"] : step["budget"] == "minus_one" ? .number(Double(lastBudget - 1)) : 1000000
                var request = merge(["request_id":"request:scenario","tuple":merge(try KDNACore.versionTuple(),step["tuple_change"]),"budget_bytes":budget,"mode":.string(mode),"selection":["whole_asset","catalog"].contains(mode) ? nil : selection,"handle":mode == "expand" ? merge(lastHandle,step["handle_change"]) : nil],step["request_change"])
                let control = KDNATrustedReadControlProvider { step.has("control") ? step["control"] : ["admission_response_limit_bytes":4096] }
                let current = step["new_snapshot"].boolean ? try XCTUnwrap(KDNACore.admitFile(file).snapshot) : snapshot
                var actual: KDNAValue = nil, attempts: [KDNAValue] = []
                for _ in 0..<8 {
                    actual = await KDNARead.readSnapshot(current, request: request, control: control, host: host)
                    attempts.append(["request":request,"result":actual])
                    if step["budget"] != "fixed_point" { break }
                    let required = try XCTUnwrap(Int(actual["envelope"]["budget"]["required_bytes"].text))
                    if Double(required) == request["budget_bytes"].numeric && outcome(actual) == "ready" { lastBudget = required; break }
                    request["budget_bytes"] = .number(Double(required))
                }
                XCTAssertEqual(outcome(actual),step["expect"].text,scenario["name"].text + "/" + step["name"].text)
                if step.has("calls") { XCTAssertEqual(calls,Int(step["calls"].numeric)) }
                let envelope = actual["envelope"], content = envelope["content"]
                if envelope != .null {
                    let size = try KDNAJSON.canonical(envelope).count
                    XCTAssertEqual(size,Int(envelope["budget"]["actual_bytes"].text))
                    XCTAssertLessThanOrEqual(Double(size),envelope["budget"]["limit_bytes"].numeric)
                    XCTAssertEqual(envelope["states"]["action_authorization"],"not_evaluated")
                }
                if outcome(actual) != "ready" { XCTAssertEqual(content,.null) }
                for role in step["required_roles"].list { XCTAssertTrue(content["closure"].list.contains { $0["role"] == role }) }
                if step.has("owners") { XCTAssertEqual(content["closure"].list.filter { $0["role"] == "judgment" }.map { $0["value"]["id"] },step["owners"].list) }
                if step.has("handles") { XCTAssertEqual(content["expansion_handles"].list.count,Int(step["handles"].numeric)) }
                if step.has("same_content_as") { XCTAssertEqual(content,prior[step["same_content_as"].text]) }
                prior[step["name"].text] = content
                var row: KDNAValue = ["scenario":scenario["name"],"step":step["name"],"calls":.number(Double(calls)),"attempts":.array(attempts),"result":actual]
                if comparison {
                    let actualText = try normalize(row), expectedText = try normalize(expected[results.count])
                    let matched = actualText == expectedText
                    XCTAssertTrue(matched,scenario["name"].text + "/" + step["name"].text + "\n" + actualText + "\nEXPECTED\n" + expectedText)
                    row["matched"] = .bool(matched)
                }
                results.append(row)
            }
        }
        if let output = ProcessInfo.processInfo.environment["KDNA_SCENARIO_OUTPUT"] {
            var data = Data()
            for row in results { data += try KDNAJSON.canonical(row); data.append(10) }
            try data.write(to: URL(fileURLWithPath: output),options:.atomic)
        }
    }
}
