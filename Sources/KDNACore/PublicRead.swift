import Foundation

public final class KDNATrustedReadControlProvider {
    fileprivate let observe: () throws -> KDNAValue
    public init(observe: @escaping () throws -> KDNAValue) { self.observe = observe }
}

public final class KDNATrustedHostReadProvider {
    fileprivate let observe: (KDNAValue, KDNASnapshot) async throws -> KDNAValue
    fileprivate let deliver: ((KDNAValue) async throws -> Bool)?
    private var handles: [KDNAKey:J] = [:]
    private var denials: Set<Data> = []
    private let lock = NSLock()
    public init(observe: @escaping (KDNAValue, KDNASnapshot) async throws -> KDNAValue,
                deliver: ((KDNAValue) async throws -> Bool)? = nil) { self.observe = observe; self.deliver = deliver }
    fileprivate func registered(_ handle: J) -> Bool {
        lock.lock(); defer { lock.unlock() }; return handles[KDNAKey(handle["handle_id"].text)] == handle
    }
    fileprivate func register(_ values: [J]) {
        lock.lock(); defer { lock.unlock() }; for value in values { handles[KDNAKey(value["handle_id"].text)] = value }
    }
    fileprivate func denied(_ key: Data, lift: Bool, deny: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if lift { denials.remove(key) }; if deny { denials.insert(key) }; return denials.contains(key)
    }
}

public final class KDNAAdmittedReadRequest {
    fileprivate let record: J
    fileprivate init(_ record: J) { self.record = record }
}

public struct KDNAReadAdmission {
    public let request: KDNAAdmittedReadRequest?
    public let result: KDNAValue
    fileprivate init(_ request: KDNAAdmittedReadRequest?, _ result: KDNAValue) { self.request = request; self.result = result }
}

private struct ReadAdmissionFailure: Error { let reason: String; let field: String }
private struct ReadFailure: Error { let code: String }

public enum KDNARead {
    private static var sequence = 0
    private static let sequenceLock = NSLock()
    private static func next() -> Int { sequenceLock.lock(); defer { sequenceLock.unlock() }; sequence += 1; return sequence }
    private static func correlation(_ id: J) -> J { identifier(id) ? ["state": "validated", "request_id": id] : ["state": "unavailable", "request_id": nil] }
    private static func result(_ channel: String, _ payload: J, admission: Bool = false) -> J {
        var r: J = ["channel": .string(channel), "admission_rejection": nil, "control": nil, "transport_failure": nil]
        r[admission ? "admitted_request" : "envelope"] = nil
        r[channel == "read_envelope" ? "envelope" : channel == "no_body_control" ? "control" : channel] = payload
        return r
    }
    private static func transport(_ cause: J, _ cor: J, admission: Bool = false) -> J { result("transport_failure", ["code": "READ_TRANSPORT_FAILURE", "semantic_cause": cause, "correlation": cor, "delivery": "not_confirmed"], admission: admission) }
    private static func size(_ value: J) throws -> Int { try KDNAJSON.canonical(value).count }
    private static func fixed(_ n: Int) -> J { .string(String(format: "%016lld", Int64(n))) }
    private static func states() -> J { ["core": "not_evaluated", "interpretation": "not_evaluated", "writer": "not_evaluated", "confirmation": "not_evaluated", "read_permission": "not_evaluated", "action_authorization": "not_evaluated"] }
    private static func assessment() -> J { ["state": "not_evaluated", "kind": nil, "assessor_id": nil, "evidence_ref": nil] }
    private static func diagnostic(_ code: String) -> J {
        let stage: String
        if ["READ_INPUT_INVALID","READ_SNAPSHOT_UNATTESTED","READ_CORE_CAPABILITY_UNAVAILABLE"].contains(code) { stage = "input" }
        else if code.contains("UNSUPPORTED_VERSION") || code.contains("MIXED_VERSION") { stage = "version" }
        else if code.contains("CORE_INVALID") || code.contains("INTERPRETATION") || code.hasPrefix("READ_COMPONENT_") || code == "READ_METHOD_PRESENCE_INVALID" { stage = "core" }
        else if !code.hasPrefix("READ_HANDLE") && (code.contains("ASSET_MISMATCH") || code.contains("ASSET_VERSION_MISMATCH") || code.contains("SELECTION_")) { stage = "selection" }
        else if ["READ_HANDLE_UNTRUSTED","READ_HANDLE_VERSION_MISMATCH","READ_HANDLE_STALE","READ_HANDLE_ASSET_MISMATCH","READ_HANDLE_SCOPE_MISMATCH"].contains(code) { stage = "handle" }
        else if code == "READ_PROJECTION_INVALID" { stage = "projection" }
        else if code == "READ_BUDGET_INSUFFICIENT" { stage = "budget" }
        else { stage = "host" }
        return ["code": .string(code), "stage": .string(stage), "severity": "error", "subject": nil, "field": nil]
    }
    private static func inspectCandidate(_ candidate: J, _ tuple: J) throws -> J {
        func fail(_ reason: String, _ field: String) throws -> Never { throw ReadAdmissionFailure(reason: reason, field: field) }
        func keys(_ value: J, _ allowed: [String], _ prefix: String, required: [String]? = nil) throws {
            guard case .object(let fields) = value else { try fail("wrong_type", prefix) }
            if fields.keys.contains(where: { !allowed.contains($0.text) }) { try fail("unknown_field", "$unknown") }
            for k in required ?? allowed where !value.has(k) { try fail("missing_required", prefix == "handle.selection" ? prefix : prefix.isEmpty ? k : prefix + "." + k) }
        }
        func id(_ value: J, _ field: String) throws {
            guard case .string = value else { try fail("wrong_type", field) }
            if !identifier(value) { try fail("invalid_identifier", field) }
        }
        func integer(_ value: J, _ field: String) throws {
            guard case .number(let n) = value else { try fail("wrong_type", field) }
            if !n.isFinite || n.rounded(.towardZero) != n || abs(n) > 9007199254740991 { try fail("unsafe_integer", field) }
            if n < 0 { try fail("out_of_range", field) }
        }
        guard case .object = candidate else { try fail("representation_not_object", "$candidate") }
        try keys(candidate, ["request_id","tuple","budget_bytes","mode","selection","handle"], "")
        try id(candidate["request_id"], "request_id"); try integer(candidate["budget_bytes"], "budget_bytes")
        let t = candidate["tuple"], tupleKeys = tuple.fields.keys.map { $0.text }.sorted()
        try keys(t, tupleKeys, "tuple", required: [])
        for k in tupleKeys where t.has(k) {
            guard case .string(let text) = t[k] else { try fail("wrong_type", "tuple." + k) }
            if !scalar(text) { try fail("invalid_identifier", "tuple." + k) }
        }
        var record: J = ["request_id": candidate["request_id"], "budget_bytes": candidate["budget_bytes"], "request": nil, "version_rejection": nil]
        if t != tuple {
            let mixed = tupleKeys.contains { $0 != "payload_profile" && t[$0] == tuple[$0] }
            record["version_rejection"] = .string(mixed ? "READ_MIXED_VERSION_TUPLE" : "READ_UNSUPPORTED_VERSION"); return record
        }
        let mode = candidate["mode"], selection = candidate["selection"], handle = candidate["handle"]
        if ![J.string("whole_asset"), "catalog", "exact_selection", "expand"].contains(mode) { try fail("mode_shape_invalid", "mode") }
        let selectionKeys = ["asset_id","asset_version","judgment_id"]
        if mode == "whole_asset" || mode == "catalog" { if selection != .null { try fail("mode_shape_invalid", "selection") } }
        else { try keys(selection, selectionKeys, "selection"); for k in selectionKeys { try id(selection[k], "selection." + k) } }
        if mode != "expand" { if handle != .null { try fail("mode_shape_invalid", "handle") } }
        else {
            let fields = ["handle_id","asset_id","asset_version","A","C","snapshot_id","core_version","ir_version","read_version","selection","target","scope","issued_at","expires_at","host_id","host_epoch"]
            try keys(handle, fields, "handle")
            for k in fields {
                let v = handle[k]
                if k == "selection" { try keys(v, selectionKeys, "handle.selection"); for field in selectionKeys { try id(v[field], "handle.selection") } }
                else if k == "scope" {
                    guard case .array(let values) = v else { try fail("wrong_type", "handle.scope") }
                    for value in values { try id(value, "handle.scope") }
                    if values.isEmpty || Set(values.map { KDNAKey($0.text) }).count != values.count { try fail("mode_shape_invalid", "handle") }
                } else if k == "issued_at" || k == "expires_at" { try integer(v, "handle." + k) }
                else if k == "A" || k == "C" {
                    guard case .string(let text) = v else { try fail("wrong_type", "handle." + k) }
                    if text.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) == nil { try fail("invalid_identifier", "handle." + k) }
                } else { try id(v, "handle." + k) }
            }
            if handle["issued_at"].numeric >= handle["expires_at"].numeric { try fail("mode_shape_invalid", "handle") }
        }
        _ = try KDNAJSON.canonical(candidate)
        record["request"] = candidate; return record
    }
    public static func admitRequest(_ candidate: KDNAValue, control: KDNATrustedReadControlProvider?) -> KDNAReadAdmission {
        let cor = correlation(candidate["request_id"])
        var record: J = nil, failure: J = nil, cause: J = nil, inspectionFailure = false
        do { record = try inspectCandidate(candidate, KDNACore.versionTuple()) }
        catch let error as ReadAdmissionFailure { failure = ["stage": "admission", "severity": "error", "reason": .string(error.reason), "field": .string(error.field)]; cause = "READ_INPUT_INVALID" }
        catch { inspectionFailure = true }
        do {
            guard let control else { throw ReadFailure(code: "READ_TRANSPORT_FAILURE") }
            let observed = try control.observe()
            try demand(PublicSchema.typeMatches(observed,"object") && observed.fields.keys.allSatisfy { $0 == "admission_response_limit_bytes" } && isUInt(observed["admission_response_limit_bytes"]))
            if inspectionFailure { return KDNAReadAdmission(nil, transport(cause, cor, admission: true)) }
            let limit = observed["admission_response_limit_bytes"]
            if failure != .null {
                var body: J = ["contract": "kdna.read-admission/0.1.0", "code": "READ_INPUT_INVALID", "diagnostic": failure, "correlation": cor, "control_budget": ["limit_bytes": limit, "actual_bytes": "0000000000000000"]]
                let count = try size(body); body["control_budget"]["actual_bytes"] = fixed(count)
                if Double(count) <= limit.numeric { return KDNAReadAdmission(nil, result("admission_rejection", body, admission: true)) }
                return KDNAReadAdmission(nil, result("no_body_control", ["code": "READ_ADMISSION_RESPONSE_TOO_SMALL", "semantic_cause": "READ_INPUT_INVALID", "correlation": cor, "body_bytes": 0], admission: true))
            }
            let request = KDNAAdmittedReadRequest(record)
            return KDNAReadAdmission(request, result("admitted_request", [:], admission: true))
        } catch { return KDNAReadAdmission(nil, transport(cause, cor, admission: true)) }
    }
    private static func inspect(_ admitted: KDNAAdmittedReadRequest?, _ snapshot: KDNASnapshot?) throws -> (J,J,J) {
        guard let admitted else { throw ReadFailure(code: "READ_INPUT_INVALID") }
        let record = admitted.record
        if record["version_rejection"] != .null { throw ReadFailure(code: record["version_rejection"].text) }
        guard let snapshot else { throw ReadFailure(code: "READ_INPUT_INVALID") }
        let view = snapshot.view, request = record["request"]
        if view["tuple"] != (try KDNACore.versionTuple()) { throw ReadFailure(code: "READ_MIXED_VERSION_TUPLE") }
        if request["selection"] != .null {
            let selected = request["selection"]
            if selected["asset_id"] != view["asset"]["asset_id"] { throw ReadFailure(code: "READ_ASSET_MISMATCH") }
            if selected["asset_version"] != view["asset"]["asset_version"] { throw ReadFailure(code: "READ_ASSET_VERSION_MISMATCH") }
            let count = view["ir"]["catalog"].list.filter { $0["judgment_id"] == selected["judgment_id"] }.count
            if count != 1 { throw ReadFailure(code: count == 0 ? "READ_SELECTION_NOT_FOUND" : "READ_SELECTION_AMBIGUOUS") }
        }
        return (view,request,record)
    }
    private static func handleFields(_ request: J, _ view: J) throws {
        let h = request["handle"]; if h == .null { return }
        let tuple = try KDNACore.versionTuple()
        if ["core","ir","read"].contains(where: { h[$0 + "_version"] != tuple[$0] }) { throw ReadFailure(code: "READ_HANDLE_VERSION_MISMATCH") }
        if h["snapshot_id"] != view["snapshot_id"] || h["A"] != view["digests"]["A"]["observed"] || h["C"] != view["digests"]["C"]["observed"] { throw ReadFailure(code: "READ_HANDLE_STALE") }
        if h["asset_id"] != view["asset"]["asset_id"] || h["asset_version"] != view["asset"]["asset_version"] || h["selection"] != request["selection"] { throw ReadFailure(code: "READ_HANDLE_ASSET_MISMATCH") }
        guard let target = view["expansion_targets"].list.first(where: { $0["target"] == h["target"] && $0["selection"] == request["selection"] }), Set(target["scope"].list.map { KDNAKey($0.text) }) == Set(h["scope"].list.map { KDNAKey($0.text) }) else { throw ReadFailure(code: "READ_HANDLE_SCOPE_MISMATCH") }
    }
    private static func body(_ request: J, _ view: J) throws -> J {
        let ir = view["ir"], nodes = try PublicIR.unique(ir["nodes"].list)
        let declarations = ir["nodes"].list.filter { $0["owner_judgment_id"] == .null && ["asset_declaration","declaration","scope","cohesion","attribution"].contains($0["role"].text) }
        var selected: J = nil, closure: [J] = [], catalog = ir["catalog"].list, omissions: [J] = []
        if request["mode"] == "exact_selection" || request["mode"] == "expand" {
            selected = request["selection"]; catalog = catalog.filter { $0["judgment_id"] == selected["judgment_id"] }
            guard let mandatory = ir["mandatory_closures"].list.first(where: { $0["selection"] == selected }) else { throw ReadFailure(code: "READ_PROJECTION_INVALID") }
            var ids = mandatory["node_ids"].list
            if request["mode"] == "expand" {
                guard let target = view["expansion_targets"].list.first(where: { $0["target"] == request["handle"]["target"] && $0["selection"] == selected }) else { throw ReadFailure(code: "READ_PROJECTION_INVALID") }
                ids = target["scope"].list
            }
            for id in ids { guard let n = nodes[KDNAKey(id.text)] else { throw ReadFailure(code: "READ_PROJECTION_INVALID") }; closure.append(n) }
        }
        for item in ir["catalog"].list where selected == .null || item["judgment_id"] != selected["judgment_id"] {
            omissions.append(["state": "explicitly_omitted", "target": item["node_ref"], "field": "judgment", "reason": selected == .null ? "not_in_mode" : "outside_selection", "expandable": false, "handle_id": nil])
        }
        if request["mode"] == "catalog" { for d in declarations { omissions.append(["state": "explicitly_omitted", "target": d["id"], "field": "declaration", "reason": "not_in_mode", "expandable": false, "handle_id": nil]) } }
        let authored = ir["nodes"].list.first { $0["role"] == "declaration" && $0["owner_judgment_id"] == .null }?["value"] ?? [:]
        let missing: [J] = ["highest_question","worldview","value_order","role","boundaries"].filter { !authored.has($0) }.map { ["state": "observed_missing", "field": .string($0)] }
        let claims = ir["nodes"].list.filter { $0["role"] == "provenance" || $0["role"] == "attribution" }
        let hasClaim = claims.contains { $0["role"] == "provenance" || $0["value"]["state"] == "provided" }
        let ids = Set(closure.map { KDNAKey($0["id"].text) })
        let relationships = ir["relationships"].list.filter { relation in relation["participants"].list.allSatisfy { p in closure.contains { $0["role"] == "judgment" && $0["value"]["id"] == p["judgment_ref"] } } }
        let content: J = ["declarations": .array(request["mode"] == "catalog" ? [] : declarations), "catalog": .array(catalog), "selected": selected, "closure": .array(closure), "references": .array(ir["references"].list.filter { ids.contains(KDNAKey($0["source_node"].text)) && ids.contains(KDNAKey($0["target_node"].text)) }), "relationships": .array(relationships), "missing": .array(missing), "provenance": ["declarations": .array(claims), "confirmation": hasClaim ? "claimed_unverified" : "not_evaluated", "verifier_id": nil, "evidence_ref": nil], "expansion_handles": []]
        return ["asset": view["asset"], "tuple": view["tuple"], "digests": view["digests"], "snapshot_id": view["snapshot_id"], "content": content, "diagnostics": [], "omissions": .array(omissions), "assessment": assessment()]
    }
    public static func project(_ request: KDNAAdmittedReadRequest?, snapshot: KDNASnapshot?) -> KDNAValue {
        do { let (view, candidate, _) = try inspect(request, snapshot); try handleFields(candidate, view); return ["status": "projected", "body": try body(candidate, view), "diagnostics": []] }
        catch let failure as ReadFailure { return ["status": "rejected", "body": nil, "diagnostics": [diagnostic(failure.code)]] }
        catch { return ["status": "rejected", "body": nil, "diagnostics": [diagnostic("READ_PROJECTION_INVALID")]] }
    }
    private static func observe(_ host: KDNATrustedHostReadProvider?, _ request: J, _ snapshot: KDNASnapshot, _ view: J) async throws -> J {
        guard let host else { throw ReadFailure(code: "READ_HOST_CONTEXT_UNTRUSTED") }
        let value = try await host.observe(request, snapshot)
        func trust(_ test: Bool) throws { if !test { throw ReadFailure(code: "READ_HOST_CONTEXT_UNTRUSTED") } }
        do { _ = try KDNAJSON.canonical(value) } catch { throw ReadFailure(code: "READ_HOST_CONTEXT_UNTRUSTED") }
        let allowed = ["host_id","host_epoch","decision_id","request_id","snapshot_id","A","C","scope","issued_at","expires_at","decision","policy_id","current_ms","revoked","lift_denial"]
        try trust(PublicSchema.typeMatches(value,"object") && value.fields.keys.allSatisfy { allowed.contains($0.text) })
        for k in ["revoked","lift_denial"] where value.has(k) { try trust(PublicSchema.typeMatches(value[k],"boolean")) }
        for k in ["host_id","host_epoch","decision_id","request_id","snapshot_id","policy_id"] { try trust(identifier(value[k])) }
        try trust(value["request_id"] == request["request_id"] && value["snapshot_id"] == view["snapshot_id"] && value["A"] == view["digests"]["A"]["observed"] && value["C"] == view["digests"]["C"]["observed"] && (value["decision"] == "allow" || value["decision"] == "deny") && PublicSchema.typeMatches(value["scope"],"array") && value["scope"].list.allSatisfy { identifier($0) } && Set(value["scope"].list.map { KDNAKey($0.text) }).count == value["scope"].list.count)
        try trust(isUInt(value["issued_at"]) && isUInt(value["expires_at"]) && value["issued_at"].numeric < value["expires_at"].numeric && value["expires_at"].numeric - value["issued_at"].numeric <= 3600000)
        let h = request["handle"]
        if h != .null && (h["host_id"] != value["host_id"] || h["host_epoch"] != value["host_epoch"]) { throw ReadFailure(code: "READ_HOST_EPOCH_MISMATCH") }
        if !isUInt(value["current_ms"]) || value["current_ms"].numeric < value["issued_at"].numeric || h != .null && value["current_ms"].numeric < h["issued_at"].numeric { throw ReadFailure(code: "READ_HOST_TIME_INVALID") }
        if h != .null && value["current_ms"].numeric >= h["expires_at"].numeric { throw ReadFailure(code: "READ_HANDLE_EXPIRED") }
        if value["current_ms"].numeric >= value["expires_at"].numeric { throw ReadFailure(code: "READ_HOST_CONTEXT_EXPIRED") }
        let key = try KDNAJSON.canonical([value["host_id"],value["host_epoch"],view["asset"]["asset_id"]])
        if host.denied(key, lift: value["lift_denial"].boolean, deny: value["revoked"].boolean || value["decision"] == "deny") { throw ReadFailure(code: "READ_HOST_DENIED") }
        return value
    }
    private static func scope(_ body: inout J, _ context: J) -> Bool {
        let allowed = Set(context["scope"].list.map { KDNAKey($0.text) })
        var content = body["content"]
        if content["closure"].list.contains(where: { !allowed.contains(KDNAKey($0["id"].text)) }) { return false }
        content["declarations"] = .array(content["declarations"].list.filter { allowed.contains(KDNAKey($0["id"].text)) })
        content["catalog"] = .array(content["catalog"].list.filter { allowed.contains(KDNAKey($0["node_ref"].text)) })
        content["provenance"]["declarations"] = .array(content["provenance"]["declarations"].list.filter { allowed.contains(KDNAKey($0["id"].text)) })
        if !content["provenance"]["declarations"].list.contains(where: { $0["role"] == "provenance" || $0["value"]["state"] == "provided" }) { content["provenance"]["confirmation"] = "not_evaluated"; content["provenance"]["verifier_id"] = nil; content["provenance"]["evidence_ref"] = nil }
        content["relationships"] = .array(content["relationships"].list.filter { relation in content["closure"].list.contains { $0["role"] == "relationship" && $0["value"]["id"] == relation["id"] && allowed.contains(KDNAKey($0["id"].text)) } })
        content["references"] = .array(content["references"].list.filter { allowed.contains(KDNAKey($0["source_node"].text)) && allowed.contains(KDNAKey($0["target_node"].text)) })
        body["omissions"] = .array(body["omissions"].list.filter { allowed.contains(KDNAKey($0["target"].text)) }); body["content"] = content
        return true
    }
    private static func rejected(_ record: J, _ code: String, _ observed: J) throws -> J {
        ["contract": try KDNACore.versionTuple()["read"], "request_id": record["request_id"], "status": "rejected", "tuple": nil, "asset": nil, "snapshot_id": nil, "digests": nil, "content": nil, "states": observed, "diagnostics": [diagnostic(code)], "omissions": [], "assessment": assessment(), "receipt": ["receipt_id": .string("receipt:" + record["request_id"].text), "request_id": record["request_id"], "snapshot_id": nil, "host_id": nil, "host_epoch": nil, "decision_id": nil, "disclosed_at": nil, "delivery": "not_delivered"], "budget": ["limit_bytes": record["budget_bytes"], "required_bytes": "0000000000000000", "actual_bytes": "0000000000000000"]]
    }
    private static func measure(_ envelope: inout J, required: Int? = nil) throws -> Int {
        envelope["budget"]["actual_bytes"] = "0000000000000000"; envelope["budget"]["required_bytes"] = required.map(fixed) ?? "0000000000000000"
        let count = try size(envelope); envelope["budget"]["actual_bytes"] = fixed(count)
        if required == nil { envelope["budget"]["required_bytes"] = fixed(count) }; return count
    }
    private static func finish(_ original: J, _ record: J) throws -> J {
        var envelope = original
        let count = try measure(&envelope), ready = envelope["status"] == "ready"
        let code = envelope["diagnostics"].list.first { $0["severity"] == "error" }?["code"] ?? nil
        var rejection = try ready ? rejected(record,"READ_BUDGET_INSUFFICIENT",envelope["states"]) : envelope
        let rejectionBytes = try ready ? measure(&rejection,required: count) : count
        if ready && code == .null && Double(count) <= record["budget_bytes"].numeric { return result("read_envelope",envelope) }
        if Double(rejectionBytes) <= record["budget_bytes"].numeric { return result("read_envelope",rejection) }
        return result("no_body_control", ["code": "READ_RESPONSE_BUDGET_TOO_SMALL", "semantic_cause": code == .null ? "READ_BUDGET_INSUFFICIENT" : code, "correlation": correlation(record["request_id"]), "body_bytes": 0])
    }
    private static func deliver(_ prepared: J, _ host: KDNATrustedHostReadProvider?) async -> J {
        guard let callback = host?.deliver, prepared["channel"] != "transport_failure" else { return prepared }
        let body = prepared["envelope"], admission = prepared["admission_rejection"], control = prepared["control"]
        let id = body["request_id"] != .null ? body["request_id"] : admission["correlation"]["request_id"] != .null ? admission["correlation"]["request_id"] : control["correlation"]["request_id"]
        let diagnosticCause = body["diagnostics"].list.first { $0["severity"] == "error" }?["code"] ?? nil
        let cause = admission["code"] != .null ? admission["code"] : diagnosticCause != .null ? diagnosticCause : control["semantic_cause"]
        do { if try await callback(prepared) { return prepared } } catch { return transport(cause,correlation(id)) }
        return transport(cause,correlation(id))
    }
    private static func run(_ admission: () -> KDNAAdmission, _ candidate: J, _ control: KDNATrustedReadControlProvider?, _ host: KDNATrustedHostReadProvider?) async -> J {
        let input = admitRequest(candidate,control: control)
        guard let admitted = input.request else {
            var failure = input.result; failure.remove("admitted_request"); failure["envelope"] = nil
            return await deliver(failure,host)
        }
        let record = admitted.record
        var state = states(), handles: [J] = []
        func prepare() async throws -> J {
            if record["version_rejection"] != .null { throw ReadFailure(code: record["version_rejection"].text) }
            let core = admission()
            guard let snapshot = core.snapshot else {
                let reason = core.result["reason"].text
                state["core"] = core.result["states"]["core"]
                state["interpretation"] = core.result["states"]["interpretation"]
                throw ReadFailure(code: reason)
            }
            state["core"] = "valid"; state["interpretation"] = "complete"
            let (view, request, _) = try inspect(admitted,snapshot)
            if request["handle"] != .null {
                if host?.registered(request["handle"]) != true { throw ReadFailure(code: "READ_HANDLE_UNTRUSTED") }
                try handleFields(request,view)
            }
            let first = try await observe(host,request,snapshot,view)
            var body = try body(request,view)
            if !scope(&body,first) { throw ReadFailure(code: "READ_SCOPE_DENIED") }
            let context = try await observe(host,request,snapshot,view)
            if !scope(&body,context) { throw ReadFailure(code: "READ_SCOPE_DENIED") }
            state["read_permission"] = "allowed"; state["confirmation"] = body["content"]["provenance"]["confirmation"]
            let tuple = try KDNACore.versionTuple()
            if request["selection"] != .null && request["mode"] != "expand" {
                for target in view["expansion_targets"].list where target["selection"]["judgment_id"] == request["selection"]["judgment_id"] && target["scope"].list.allSatisfy({ context["scope"].list.contains($0) }) {
                    handles.append(["handle_id": .string("handle:" + view["snapshot_id"].text + ":" + String(next())), "asset_id": view["asset"]["asset_id"], "asset_version": view["asset"]["asset_version"], "A": view["digests"]["A"]["observed"], "C": view["digests"]["C"]["observed"], "snapshot_id": view["snapshot_id"], "core_version": tuple["core"], "ir_version": tuple["ir"], "read_version": tuple["read"], "selection": request["selection"], "target": target["target"], "scope": target["scope"], "issued_at": context["current_ms"], "expires_at": .number(min(context["expires_at"].numeric,context["current_ms"].numeric + 3600000)), "host_id": context["host_id"], "host_epoch": context["host_epoch"]])
                }
            }
            body["content"]["expansion_handles"] = .array(handles)
            var envelope = body
            envelope["contract"] = tuple["read"]; envelope["request_id"] = record["request_id"]; envelope["status"] = "ready"; envelope["states"] = state
            envelope["receipt"] = ["receipt_id": .string("receipt:" + view["snapshot_id"].text + ":" + String(next())), "request_id": record["request_id"], "snapshot_id": view["snapshot_id"], "host_id": context["host_id"], "host_epoch": context["host_epoch"], "decision_id": context["decision_id"], "disclosed_at": context["current_ms"], "delivery": "delivered"]
            envelope["budget"] = ["limit_bytes": record["budget_bytes"], "required_bytes": "0000000000000000", "actual_bytes": "0000000000000000"]
            return try finish(envelope,record)
        }
        let prepared: J
        do { prepared = try await prepare() }
        catch let failure as ReadFailure {
            if failure.code == "READ_HOST_DENIED" { state["read_permission"] = "denied" }
            do { prepared = try finish(rejected(record,failure.code,state),record) }
            catch { return transport(.string(failure.code),correlation(record["request_id"])) }
        } catch { return transport(nil,correlation(record["request_id"])) }
        let delivered = await deliver(prepared,host)
        if delivered == prepared && prepared["channel"] == "read_envelope" && prepared["envelope"]["status"] == "ready" { host?.register(handles) }
        return delivered
    }
    public static func readBytes(_ bytes: Data, request: KDNAValue, control: KDNATrustedReadControlProvider?, host: KDNATrustedHostReadProvider?) async -> KDNAValue { await run({ KDNACore.admitBytes(bytes) },request,control,host) }
    public static func readFile(_ url: URL, request: KDNAValue, control: KDNATrustedReadControlProvider?, host: KDNATrustedHostReadProvider?) async -> KDNAValue { await run({ KDNACore.admitFile(url) },request,control,host) }
    public static func readSnapshot(_ snapshot: KDNASnapshot?, request: KDNAValue, control: KDNATrustedReadControlProvider?, host: KDNATrustedHostReadProvider?) async -> KDNAValue {
        await run({ snapshot.map { KDNAAdmission($0,["status":"accepted"]) } ?? KDNACore.rejected("READ_INPUT_INVALID") },request,control,host)
    }
}
