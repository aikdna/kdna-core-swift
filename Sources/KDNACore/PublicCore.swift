import Foundation
import Darwin

/// Only this module's successful bytes admission can construct this immutable
/// snapshot. Serialized fields do not confer Core admission authority.
public final class KDNASnapshot {
    let view: KDNAValue
    fileprivate init(_ view: KDNAValue) { self.view = view }
    public func inspect() -> KDNAValue { view }
}

public struct KDNAAdmission {
    public let snapshot: KDNASnapshot?
    public let result: KDNAValue
    init(_ snapshot: KDNASnapshot?, _ result: KDNAValue) { self.snapshot = snapshot; self.result = result }
}

public enum KDNACore {
    static let loadedContract: Result<J, Error> = Result { try PublicSchema.contract() }
    public static func versionTuple() throws -> KDNAValue { try loadedContract.get()["versionTuple"] }
    public static func componentSemanticsContract() throws -> KDNAValue { try PublicComponents.descriptor(loadedContract.get()) }
    static func rejected(_ code: String = "READ_CORE_INVALID", componentFailure: J = nil) -> KDNAAdmission {
        let allowed = ["READ_INPUT_INVALID", "READ_CORE_INVALID", "READ_CORE_CAPABILITY_UNAVAILABLE", "READ_INTERPRETATION_INCOMPLETE"] + Array(PublicComponents.codes.values)
        let reason = allowed.contains(code) ? code : "READ_CORE_INVALID"
        let stage = ["READ_INPUT_INVALID", "READ_CORE_CAPABILITY_UNAVAILABLE"].contains(reason) ? "input" : "core"
        let semanticFailure = reason == "READ_INTERPRETATION_INCOMPLETE" || PublicComponents.codes.values.contains(reason)
        let states: J = ["core": semanticFailure ? "valid" : reason == "READ_CORE_INVALID" ? "invalid" : "not_evaluated", "interpretation": semanticFailure ? "blocked" : "not_evaluated"]
        return KDNAAdmission(nil, ["status": "rejected", "reason": .string(reason), "states": states, "component_failure": PublicComponents.codes.values.contains(reason) ? componentFailure : nil, "diagnostics": [["code": .string(reason), "stage": .string(stage), "severity": "error", "subject": nil, "field": nil]]])
    }
    public static func admitBytes(_ data: Data) -> KDNAAdmission {
        do {
            let entries = try PublicContainer.parse(data), contract = try loadedContract.get()
            guard let manifestBytes = entries["kdna.json"], let payloadBytes = entries["payload.kdnab"] else { return rejected() }
            let manifest = try KDNAJSON.parse(manifestBytes)
            try PublicSchema.validate("Manifest", manifest, contract)
            if manifest["payload"]["encrypted"].boolean || manifest.has("encryption") || entries["signature.kdsig"] != nil || entries["checksums.json"] != nil { return rejected("READ_CORE_CAPABILITY_UNAVAILABLE") }
            var decoder = PublicCBOR(bytes: Array(payloadBytes)); let payload = try decoder.decode()
            try PublicSchema.validate("Payload", payload, contract)
            for (a, m) in [("asset_id","asset_id"),("asset_version","version"),("judgment_version","judgment_version")] { try demand(payload["asset"][a] == manifest[m]) }
            let A = sha(data), C = sha(try PublicDigests.content(entries)), E = sha(try PublicDigests.runtime(entries, manifest))
            for expected in [manifest["content_digest"], manifest["authoring"]["content_digest"]] where expected != .null && !expected.text.isEmpty { try demand(expected == .string(C)) }
            let ir = try PublicIR.build(manifest, payload, entries, contract)
            let view: J = ["snapshot_id": .string("snapshot:" + UUID().uuidString.lowercased()), "tuple": contract["versionTuple"], "asset": payload["asset"], "digests": ["A": PublicDigests.evidence("A", A), "C": PublicDigests.evidence("C", C, expected: manifest["content_digest"]), "E": PublicDigests.evidence("E", E)], "ir": ir, "ir_digest": .string(sha(try KDNAJSON.canonical(ir))), "runtime_entry_names": .array(try PublicDigests.runtimeNames(entries, manifest).map { .string($0.text) }), "expansion_targets": ir["expansion_targets"]]
            return KDNAAdmission(KDNASnapshot(view), ["status": "accepted"])
        } catch let failure as PublicFailure { return rejected(failure.code, componentFailure: failure.componentFailure) }
        catch { return rejected() }
    }
    public static func admitFile(_ url: URL) -> KDNAAdmission {
        guard url.isFileURL else { return rejected("READ_INPUT_INVALID") }
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { handle.closeFile() }
            var info = stat()
            try demand(fstat(handle.fileDescriptor, &info) == 0 && info.st_mode & S_IFMT == S_IFREG && info.st_size <= PublicContainer.maximumBytes)
            var bytes = Data()
            while true {
                guard let part = try handle.read(upToCount: PublicContainer.maximumBytes + 1 - bytes.count), !part.isEmpty else { break }
                bytes += part; try demand(bytes.count <= PublicContainer.maximumBytes)
            }
            return admitBytes(bytes)
        } catch let failure as PublicFailure { return rejected(failure.code, componentFailure: failure.componentFailure) }
        catch { return rejected() }
    }
    /// No admitted Plan or execution capability exists in the accepted RC.
    /// This is an implementation capability result, not a new public Plan wire.
    public static func planCapability() -> KDNAValue { ["status": "unavailable", "code": "KDNA_PLAN_ADMISSION_UNAVAILABLE", "action_authorized": false, "creation_accepted": false] }
}
