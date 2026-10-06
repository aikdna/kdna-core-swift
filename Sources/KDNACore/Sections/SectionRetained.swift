import Foundation

// The retained read preparation (retained-sections-node.js +
// retained-state.js + retained-common.js, @aikdna/kdna-core@0.36.0): the
// closed request admission with the version-tuple rules, the authority with
// the signature policy, and the preparation — the normalization, the
// descriptor/plan projection, the read intent and the authority context the
// callback receives, then the prepared receipt with the signature-policy
// check against the immutable origin receipt. The one-shot phase machine
// (available → reserved → closed) is carried for the execution half, which
// belongs to the protected-payload subsystem and stays closed here.
public final class KDNARetainedRequest {
    let data: J
    fileprivate init(_ data: J) { self.data = data }
}
public final class KDNARetainedAuthority {
    let callback: (KDNAValue) async throws -> Bool?
    let policy: J
    fileprivate init(_ callback: @escaping (KDNAValue) async throws -> Bool?, _ policy: J) {
        self.callback = callback; self.policy = policy
    }
}
public final class KDNARetainedPreparedRead {
    enum Phase { case available, reserved, closed }
    var phase: Phase = .available
    var snapshot: KDNASectionSnapshot?
    var view: J?
    var request: J?
    var plan: J?
    var data: J?
    fileprivate init() {}
}
public enum RetainedAdmission {
    case admitted(KDNARetainedRequest)
    case rejected(KDNAValue)
}
public enum RetainedPreparationResult {
    case prepared(KDNARetainedPreparedRead)
    case rejected(KDNAValue)
}
enum SectionRetained {
    static var contractDescriptor: J {
        get throws {
            let contract = try RetainedContract.loadedContract.get()
            return ["id": contract["module"]["version"]["contract_id"], "version": contract["module"]["version"]["contract_version"],
                    "definition_digest": .string(sha(try KDNAJSON.canonical(contract["module"])))]
        }
    }
    static func failure(_ request: J?, _ detail: String, _ code: String = "READ_CORE_CAPABILITY_UNAVAILABLE", _ stage: String = "core") throws -> J {
        let diagnostic: J = ["code": .string(code), "stage": .string(stage), "severity": "error", "subject": .null, "field": .null]
        let result: J = ["contract": try contractDescriptor, "status": "rejected",
                         "request_id": request?["request_id"] ?? .null, "diagnostic": diagnostic,
                         "detail": .string(detail), "body": .null, "body_bytes": .number(0)]
        _ = try RetainedContract.validate("RetainedSectionFailure06", result)
        return result
    }
    static func admit(_ candidate: J) -> RetainedAdmission {
        let request = candidate
        do {
            try demand(identifier(request["request_id"]), "READ_INPUT_INVALID")
            guard request.fields.count == 6, ["request_id", "tuple", "budget_bytes", "mode", "selection", "handle"].allSatisfy({ request.has($0) }) else {
                throw PublicFailure("READ_INPUT_INVALID")
            }
            try demand(isUInt(request["budget_bytes"]), "READ_INPUT_INVALID")
            let tuple = try SectionContract.loadedContract.get()["module"]["versionTuple"]
            let tupleKeys = tuple.fields.keys.map { $0.text }
            try demand(request["tuple"].fields.keys.allSatisfy { tupleKeys.contains($0.text) }
                && tupleKeys.allSatisfy { request["tuple"][$0] != .null } && request["tuple"].fields.values.allSatisfy { $0 != .null }, "READ_INPUT_INVALID")
            if !RetainedPlan.same(request["tuple"], tuple) {
                let baseline = try SemanticContract.loadedContract.get()
                var historical: [J] = [baseline["versionTuple"]]
                for variant in baseline["types"]["UnsupportedVersionTuple"]["anyOf"].list {
                    var value: J = [:]
                    for (key, shape) in variant["properties"].fields { value[key.text] = shape["const"] }
                    historical.append(value)
                }
                let isHistorical = historical.contains { RetainedPlan.same($0, request["tuple"]) }
                let mixed = !isHistorical && tuple.fields.keys.contains { $0.text != "payload_profile" && RetainedPlan.same(request["tuple"][$0.text], tuple[$0.text]) }
                return .rejected(try failure(request, mixed ? "mixed_tuple" : "version_unsupported",
                                             mixed ? "READ_MIXED_VERSION_TUPLE" : "READ_UNSUPPORTED_VERSION", "version"))
            }
            _ = try RetainedContract.validate("RetainedSectionRequest06", request)
        } catch {
            let requestId = identifier(request["request_id"]) ? request : .null
            return .rejected((try? failure(requestId, "input_invalid", "READ_INPUT_INVALID", "input")) ?? .null)
        }
        return .admitted(KDNARetainedRequest(request))
    }
    static func createAuthority(_ callback: @escaping (KDNAValue) async throws -> Bool?, _ signaturePolicy: KDNAValue?) throws -> KDNARetainedAuthority {
        let policy = try SectionSignatures.policy(signaturePolicy ?? SectionSignatures.defaultPolicy)
        return KDNARetainedAuthority(callback, policy)
    }
    static func originFor(_ view: J, _ kind: String) throws -> J {
        ["snapshot_id": view["snapshot_id"], "kind": .string(kind),
         "capture_id": view["verification"]["capture"]["capture_id"],
         "admission_request_digest": view["verification"]["request_digest"],
         "verification_digest": .string(sha(try KDNAJSON.canonical(view["verification"]))),
         "checked_sections_digest": .string(sha(try KDNAJSON.canonical(view["verification"]["checked_sections"])))]
    }
    static func prepare(_ snapshot: KDNASectionSnapshot, _ request: KDNARetainedRequest, _ authority: KDNARetainedAuthority) async -> RetainedPreparationResult {
        let raw = request.data
        let wholeView = snapshot.view["ir"] != .null ? snapshot.view : .null
        var view: J
        var kind: String
        if wholeView != .null {
            view = wholeView; kind = "whole"
        } else if snapshot.view["catalog"] != .null && snapshot.view["verification"]["mode"].text == "catalog" {
            view = snapshot.view; kind = "catalog"
        } else {
            return .rejected((try? failure(raw, "origin_scope_insufficient")) ?? .null)
        }
        if kind == "catalog" && raw["mode"].text != "catalog" {
            return .rejected((try? failure(raw, "origin_scope_insufficient")) ?? .null)
        }
        var request: J, origin: J, plan: J, intent: J, context: J
        do {
            request = try RetainedPlan.normalize(raw, view)
            origin = try originFor(view, kind)
            if request["mode"].text == "expand" {
                try demand(RetainedPlan.same(request["handle"]["origin"], origin), "READ_HANDLE_STALE")
            }
            plan = try RetainedPlan.plan(request, view)
            intent = ["operation": "read_retained", "operation_id": .string("retained:" + UUID().uuidString.lowercased()), "origin": origin,
                      "request_digest": .string(sha(try KDNAJSON.canonical(request))), "mode": request["mode"],
                      "projection_node_ids": plan["node_ids"], "descriptor_node_ids": plan["descriptor_ids"],
                      "issuable_handle_scopes": plan["targets"], "physical_reads": "none", "protected_operation": false]
            context = ["contract": try contractDescriptor, "request": request, "asset": view["asset"], "tuple": view["tuple"], "intent": intent,
                       "intent_digest": .string(sha(try KDNAJSON.canonical(intent))), "signature_policy": authority.policy,
                       "signature_policy_digest": .string(sha(try KDNAJSON.canonical(authority.policy)))]
            _ = try RetainedContract.validate("RetainedSectionAuthorityContext06", context)
        } catch let failureValue as PublicFailure where failureValue.code.hasPrefix("READ_ASSET_") || failureValue.code.hasPrefix("READ_SELECTION_") || failureValue.code.hasPrefix("READ_HANDLE_") {
            let handle = failureValue.code.hasPrefix("READ_HANDLE")
            return .rejected((try? failure(raw, handle ? "handle_invalid" : "input_invalid", failureValue.code, handle ? "handle" : "selection")) ?? .null)
        } catch {
            return .rejected((try? failure(raw, "internal_capability_unavailable")) ?? .null)
        }
        let granted: Bool?
        do { granted = try await authority.callback(context) } catch { granted = false }
        guard granted == true else {
            return .rejected((try? failure(request, "authority_denied")) ?? .null)
        }
        do {
            let receipt = view["verification"]["signature_integrity"]
            let pin: J = authority.policy["expectedPublicKeyHex"]
            if (authority.policy["requireSignature"].boolean || pin != .null)
                && (receipt == .null || receipt["status"].text == "absent" || (pin != .null && !exact(receipt["public_key"].text, pin.text))) {
                return .rejected((try? failure(request, "signature_policy_unsatisfied", "READ_CORE_INVALID")) ?? .null)
            }
            let check: J = ["basis": "immutable_origin_signature_receipt", "policy": authority.policy,
                            "policy_digest": .string(sha(try KDNAJSON.canonical(authority.policy))),
                            "origin_receipt_digest": .string(sha(try KDNAJSON.canonical(receipt))), "result": "satisfied", "new_signature_verification": false]
            let data: J = ["contract": try contractDescriptor, "request": request, "request_digest": intent["request_digest"],
                           "origin": origin, "intent": intent, "intent_digest": context["intent_digest"],
                           "asset": view["asset"], "tuple": view["tuple"], "signature_policy_check": check]
            _ = try RetainedContract.validate("RetainedSectionPreparationData06", data)
            let prepared = KDNARetainedPreparedRead()
            prepared.snapshot = snapshot; prepared.view = view; prepared.request = request; prepared.plan = plan; prepared.data = data
            return .prepared(prepared)
        } catch {
            return .rejected((try? failure(request, "internal_capability_unavailable")) ?? .null)
        }
    }
    static func inspectPreparation(_ prepared: KDNARetainedPreparedRead) -> J? { prepared.data }
}
