import Foundation
import CryptoKit

public struct KDNALoadEnvironment: Equatable {
    public var hasPassword: Bool
    public var entitlementStatus: String?

    public init(hasPassword: Bool = false, entitlementStatus: String? = nil) {
        self.hasPassword = hasPassword
        self.entitlementStatus = entitlementStatus
    }
}

public struct KDNALoadPlanAsset: Codable, Equatable {
    public let asset_id: String?
    public let asset_uid: String?
    public let title: String?
    public let version: String?
    public let judgment_version: String?
}

public struct KDNALoadPlanChecks: Codable, Equatable {
    public var format_valid: Bool
    public var schema_valid: Bool
    public var payload_valid: Bool
    public var checksums_valid: Bool
    public var load_contract_valid: Bool
    public var overall_valid: Bool
}

public struct KDNALoadPlanIssue: Codable, Equatable {
    public let code: String
    public let severity: String
    public let message: String
}

public struct KDNALoadPlanSource: Codable, Equatable {
    public let kind: String?
    public let path: String
}

public struct KDNALoadPlan: Codable, Equatable {
    public let kdna_version: String?
    public let asset: KDNALoadPlanAsset
    public var access: String?
    public let access_alias: String?
    public let entitlement_profile: String?
    public var state: String
    public var required_action: String
    public var can_load_now: Bool
    public var projection_policy: String
    public var checks: KDNALoadPlanChecks
    public var issues: [KDNALoadPlanIssue]
    public let source: KDNALoadPlanSource
}

public struct KDNACredential: Equatable {
    public let password: String?
    public let entitlementStatus: String?

    public init(password: String? = nil, entitlementStatus: String? = nil) {
        self.password = password
        self.entitlementStatus = entitlementStatus
    }

    public static let none = KDNACredential()
}

public struct KDNAProjectionSection: Codable, Equatable {
    public let id: String
    public let title: String
    public let items: [String]
}

public struct KDNAJudgmentProjection: Codable, Equatable {
    public let asset: KDNALoadPlanAsset
    public let access: String?
    public let payload_profile: String?
    public let projection_policy: String
    public let sections: [KDNAProjectionSection]
    public let prompt: String
    public let source: KDNALoadPlanSource
}

public enum KDNALoadError: Error, Equatable, LocalizedError {
    case notAuthorized(KDNALoadPlan)
    case invalidPayload(String)
    case unsupportedPayloadProfile(String?)

    public var errorDescription: String? {
        switch self {
        case .notAuthorized(let plan):
            return "KDNA asset cannot load now: \(plan.required_action)"
        case .invalidPayload(let reason):
            return "KDNA payload is invalid: \(reason)"
        case .unsupportedPayloadProfile(let profile):
            return "Unsupported KDNA payload profile: \(profile ?? "null")"
        }
    }
}

public enum KDNARuntime {
    public static func planLoad(assetURL: URL, environment: KDNALoadEnvironment = KDNALoadEnvironment()) -> KDNALoadPlan {
        KDNALoadPlanCore.planLoad(assetURL: assetURL, environment: environment)
    }

    public static func loadWithCredential(
        assetURL: URL,
        credential: KDNACredential = .none
    ) throws -> KDNAJudgmentProjection {
        try KDNALoadPlanCore.loadWithCredential(assetURL: assetURL, credential: credential)
    }
}

public enum KDNALoadPlanCore {
    public static let v1MimeType = "application/vnd.kdna.asset"

    public static func planLoad(assetURL: URL, environment: KDNALoadEnvironment = KDNALoadEnvironment()) -> KDNALoadPlan {
        guard let layout = readV1Layout(assetURL: assetURL) else {
            return invalidPlan(assetURL: assetURL, message: "not a KDNA Core v1 runtime asset")
        }

        let manifest = layout.manifest
        let checks = validate(layout: layout)
        let accessInfo = normalizeAccess(manifest["access"] as? String)
        let entitlementProfile = inferEntitlementProfile(manifest: manifest)

        var plan = KDNALoadPlan(
            kdna_version: manifest["kdna_version"] as? String,
            asset: KDNALoadPlanAsset(
                asset_id: manifest["asset_id"] as? String,
                asset_uid: manifest["asset_uid"] as? String,
                title: manifest["title"] as? String,
                version: manifest["version"] as? String,
                judgment_version: manifest["judgment_version"] as? String
            ),
            access: accessInfo.access,
            access_alias: accessInfo.alias,
            entitlement_profile: entitlementProfile,
            state: "invalid",
            required_action: "block",
            can_load_now: false,
            projection_policy: "none",
            checks: checks.result,
            issues: accessInfo.alias == nil ? [] : [
                KDNALoadPlanIssue(
                    code: "KDNA_AUTH_ACCESS_ALIAS",
                    severity: "info",
                    message: "Access value \"\(accessInfo.alias!)\" is treated as \"\(accessInfo.access ?? "")\"."
                )
            ],
            source: KDNALoadPlanSource(kind: layout.sourceKind, path: assetURL.path)
        )

        if !checks.result.overall_valid {
            plan.issues.append(contentsOf: checks.problems.map {
                KDNALoadPlanIssue(code: validationProblemCode($0), severity: "blocking", message: $0)
            })
            return plan
        }

        guard let access = plan.access, ["public", "licensed", "remote"].contains(access) else {
            let unknownAccess = plan.access ?? "null"
            plan.access = nil
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_ACCESS_MODE_UNKNOWN",
                severity: "blocking",
                message: "Unknown access value \"\(unknownAccess)\"."
            ))
            return plan
        }

        if access == "remote" {
            plan.state = "needs_runtime"
            plan.required_action = "connect_runtime"
            plan.projection_policy = "remote"
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_AUTH_REMOTE_RUNTIME_REQUIRED",
                severity: "blocking",
                message: "Remote assets require a runtime projection endpoint."
            ))
            return plan
        }

        if access == "licensed" {
            return planLicensed(plan: plan, environment: environment)
        }

        if hasEncryptedPayload(manifest: manifest) {
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_CRYPTO_PROFILE_UNSUPPORTED",
                severity: "blocking",
                message: "Encrypted entries require licensed access."
            ))
            return plan
        }

        plan.state = "ready"
        plan.required_action = "load"
        plan.can_load_now = true
        plan.projection_policy = "minimal"
        return plan
    }

    public static func loadWithCredential(
        assetURL: URL,
        credential: KDNACredential = .none
    ) throws -> KDNAJudgmentProjection {
        let environment = KDNALoadEnvironment(
            hasPassword: credential.password != nil,
            entitlementStatus: credential.entitlementStatus
        )
        let plan = planLoad(assetURL: assetURL, environment: environment)
        guard plan.can_load_now else {
            throw KDNALoadError.notAuthorized(plan)
        }
        guard let layout = readV1Layout(assetURL: assetURL) else {
            throw KDNALoadError.invalidPayload("runtime layout could not be read")
        }
        guard let payload = try? JSONSerialization.jsonObject(with: layout.payload) as? [String: Any] else {
            throw KDNALoadError.invalidPayload("payload.kdnab is not a JSON object")
        }

        let profile = payload["profile"] as? String
        guard profile == "judgment-profile-v1" else {
            throw KDNALoadError.unsupportedPayloadProfile(profile)
        }

        let sections = buildProjectionSections(payload: payload)
        return KDNAJudgmentProjection(
            asset: plan.asset,
            access: plan.access,
            payload_profile: profile,
            projection_policy: plan.projection_policy,
            sections: sections,
            prompt: renderProjectionPrompt(sections: sections),
            source: plan.source
        )
    }

    private struct V1SourceLayout {
        let sourceKind: String
        let manifest: [String: Any]
        let payload: Data
        let checksums: [String: Any]?
        let rawManifest: Data
        let rawMimeType: Data
    }

    private static func readV1Layout(assetURL: URL) -> V1SourceLayout? {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: assetURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return readV1ZipLayout(assetURL: assetURL)
        }

        let manifestURL = assetURL.appendingPathComponent("kdna.json")
        let payloadURL = assetURL.appendingPathComponent("payload.kdnab")
        let mimeURL = assetURL.appendingPathComponent("mimetype")

        guard let manifestData = try? Data(contentsOf: manifestURL),
              let payloadData = try? Data(contentsOf: payloadURL),
              let mimeData = try? Data(contentsOf: mimeURL),
              let manifest = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            return nil
        }

        let checksumsURL = assetURL.appendingPathComponent("checksums.json")
        let checksums: [String: Any]?
        if let checksumsData = try? Data(contentsOf: checksumsURL) {
            checksums = (try? JSONSerialization.jsonObject(with: checksumsData)) as? [String: Any]
        } else {
            checksums = nil
        }

        return V1SourceLayout(
            sourceKind: "dir",
            manifest: manifest,
            payload: payloadData,
            checksums: checksums,
            rawManifest: manifestData,
            rawMimeType: mimeData
        )
    }

    private static func readV1ZipLayout(assetURL: URL) -> V1SourceLayout? {
        let reader = KDNAAssetReader()
        guard let asset = try? reader.open(url: assetURL),
              let mimeData = try? reader.readEntry(asset: asset, name: "mimetype"),
              let manifestData = try? reader.readEntry(asset: asset, name: "kdna.json"),
              let payloadData = try? reader.readEntry(asset: asset, name: "payload.kdnab"),
              let manifest = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            return nil
        }

        let checksums: [String: Any]?
        if let checksumsData = try? reader.readEntry(asset: asset, name: "checksums.json") {
            checksums = (try? JSONSerialization.jsonObject(with: checksumsData)) as? [String: Any]
        } else {
            checksums = nil
        }

        return V1SourceLayout(
            sourceKind: "file",
            manifest: manifest,
            payload: payloadData,
            checksums: checksums,
            rawManifest: manifestData,
            rawMimeType: mimeData
        )
    }

    private static func invalidPlan(assetURL: URL, message: String) -> KDNALoadPlan {
        KDNALoadPlan(
            kdna_version: nil,
            asset: KDNALoadPlanAsset(asset_id: nil, asset_uid: nil, title: nil, version: nil, judgment_version: nil),
            access: nil,
            access_alias: nil,
            entitlement_profile: nil,
            state: "invalid",
            required_action: "block",
            can_load_now: false,
            projection_policy: "none",
            checks: KDNALoadPlanChecks(
                format_valid: false,
                schema_valid: false,
                payload_valid: false,
                checksums_valid: false,
                load_contract_valid: false,
                overall_valid: false
            ),
            issues: [KDNALoadPlanIssue(code: "KDNA_FORMAT_INVALID", severity: "blocking", message: message)],
            source: KDNALoadPlanSource(kind: nil, path: assetURL.path)
        )
    }

    private static func validate(layout: V1SourceLayout) -> (result: KDNALoadPlanChecks, problems: [String]) {
        var result = KDNALoadPlanChecks(
            format_valid: true,
            schema_valid: true,
            payload_valid: true,
            checksums_valid: true,
            load_contract_valid: true,
            overall_valid: true
        )
        var problems: [String] = []

        if String(data: layout.rawMimeType, encoding: .utf8) != v1MimeType {
            result.format_valid = false
            problems.append("format: mimetype is not \(v1MimeType)")
        }

        if (try? JSONSerialization.jsonObject(with: layout.payload)) == nil {
            result.payload_valid = false
            problems.append("payload: not valid JSON")
        }

        if let checksums = layout.checksums {
            if (checksums["algorithm"] as? String ?? "sha256") != "sha256" {
                result.checksums_valid = false
                problems.append("checksums: unsupported digest algorithm \(checksums["algorithm"] ?? "") (supported: sha256)")
            }
            verifyDigest(
                key: "manifest_digest",
                entryName: "kdna.json",
                bytes: layout.rawManifest,
                checksums: checksums,
                result: &result,
                problems: &problems
            )
            verifyDigest(
                key: "payload_digest",
                entryName: "payload.kdnab",
                bytes: layout.payload,
                checksums: checksums,
                result: &result,
                problems: &problems
            )
        }

        result.overall_valid = result.format_valid &&
            result.schema_valid &&
            result.payload_valid &&
            result.checksums_valid &&
            result.load_contract_valid
        return (result, problems)
    }

    private static func verifyDigest(
        key: String,
        entryName: String,
        bytes: Data,
        checksums: [String: Any],
        result: inout KDNALoadPlanChecks,
        problems: inout [String]
    ) {
        guard let declared = checksums[key] as? String else { return }
        let expected = declared.replacingOccurrences(of: "sha256:", with: "")
        let actual = sha256Hex(bytes)
        if actual != expected {
            result.checksums_valid = false
            problems.append("checksums: \(key) mismatch (declared \(String(expected.prefix(8)))..., actual \(String(actual.prefix(8)))...)")
        }
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func normalizeAccess(_ access: String?) -> (access: String?, alias: String?) {
        let value = access ?? "public"
        if value == "open" { return ("public", value) }
        if value == "protected" { return ("licensed", value) }
        if value == "runtime" { return ("remote", value) }
        return (value, nil)
    }

    private static func inferEntitlementProfile(manifest: [String: Any]) -> String? {
        if let entitlement = manifest["entitlement"] as? [String: Any],
           let profile = entitlement["profile"] as? String {
            return profile
        }
        if let encryption = manifest["encryption"] as? [String: Any],
           encryption["profile"] as? String == "kdna-password-protected-v1" {
            return "password"
        }
        if manifest["access"] as? String == "protected" {
            return "password"
        }
        return nil
    }

    private static func hasEncryptedPayload(manifest: [String: Any]) -> Bool {
        if let payload = manifest["payload"] as? [String: Any],
           payload["encrypted"] as? Bool == true {
            return true
        }
        if let encryption = manifest["encryption"] as? [String: Any],
           let entries = encryption["encrypted_entries"] as? [Any],
           !entries.isEmpty {
            return true
        }
        return false
    }

    private static func planLicensed(plan initialPlan: KDNALoadPlan, environment: KDNALoadEnvironment) -> KDNALoadPlan {
        var plan = initialPlan
        let knownProfiles = Set(["password", "local_receipt", "account", "org", "purchase_receipt", "device_bound"])

        if let profile = plan.entitlement_profile, !knownProfiles.contains(profile) {
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_ENTITLEMENT_PROFILE_UNKNOWN",
                severity: "blocking",
                message: "Unknown entitlement profile \"\(profile)\"."
            ))
            return plan
        }

        if plan.entitlement_profile == "password" {
            if environment.hasPassword {
                plan.issues.append(KDNALoadPlanIssue(
                    code: "KDNA_AUTH_PASSWORD_DIAGNOSTIC",
                    severity: "info",
                    message: "hasPassword is a diagnostic credential-presence signal only; it does not verify the password."
                ))
                plan.state = "ready"
                plan.required_action = "load"
                plan.can_load_now = true
                plan.projection_policy = "minimal"
            } else {
                plan.state = "needs_password"
                plan.required_action = "enter_password"
                plan.issues.append(KDNALoadPlanIssue(
                    code: "KDNA_AUTH_PASSWORD_REQUIRED",
                    severity: "blocking",
                    message: "A password is required before this asset can be loaded."
                ))
            }
            return plan
        }

        if plan.entitlement_profile == "account" {
            plan.state = "needs_account"
            plan.required_action = "sign_in_or_activate"
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_AUTH_ACCOUNT_REQUIRED",
                severity: "blocking",
                message: "Account authorization is required before this asset can be loaded."
            ))
            return plan
        }

        if plan.entitlement_profile == "org" {
            plan.state = "needs_org_auth"
            plan.required_action = "sign_in_or_activate"
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_AUTH_ORG_REQUIRED",
                severity: "blocking",
                message: "Organization authorization is required before this asset can be loaded."
            ))
            return plan
        }

        if environment.entitlementStatus == "active" {
            plan.state = "ready"
            plan.required_action = "load"
            plan.can_load_now = true
            plan.projection_policy = "minimal"
            return plan
        }

        if environment.entitlementStatus == "expired" {
            plan.state = "expired"
            plan.required_action = "sync"
            plan.issues.append(KDNALoadPlanIssue(code: "KDNA_AUTH_EXPIRED", severity: "blocking", message: "The entitlement is expired."))
            return plan
        }

        if environment.entitlementStatus == "revoked" {
            plan.state = "revoked"
            plan.required_action = "block"
            plan.issues.append(KDNALoadPlanIssue(code: "KDNA_AUTH_REVOKED", severity: "blocking", message: "The entitlement has been revoked."))
            return plan
        }

        if environment.entitlementStatus == "offline_grace" {
            plan.state = "offline_grace"
            plan.required_action = "sync"
            plan.can_load_now = true
            plan.projection_policy = "minimal"
            plan.issues.append(KDNALoadPlanIssue(
                code: "KDNA_AUTH_OFFLINE_GRACE_ACTIVE",
                severity: "warning",
                message: "The entitlement can load during offline grace but must sync before grace expires."
            ))
            return plan
        }

        plan.state = "needs_license"
        plan.required_action = plan.entitlement_profile == "local_receipt" ? "install_receipt" : "sign_in_or_activate"
        plan.issues.append(KDNALoadPlanIssue(
            code: "KDNA_AUTH_ENTITLEMENT_REQUIRED",
            severity: "blocking",
            message: "A valid entitlement is required before this asset can be loaded."
        ))
        return plan
    }

    private static func validationProblemCode(_ problem: String) -> String {
        if problem.localizedCaseInsensitiveContains("checksums:") { return "KDNA_INTEGRITY_DIGEST_FAILED" }
        if problem.localizedCaseInsensitiveContains("signature") { return "KDNA_INTEGRITY_SIGNATURE_FAILED" }
        return "KDNA_FORMAT_INVALID"
    }

    private static func buildProjectionSections(payload: [String: Any]) -> [KDNAProjectionSection] {
        var sections: [KDNAProjectionSection] = []

        if let core = payload["core"] as? [String: Any] {
            var items: [String] = []
            if let highestQuestion = core["highest_question"] as? String,
               !highestQuestion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                items.append("Question: \(highestQuestion)")
            }
            for axiom in core["axioms"] as? [[String: Any]] ?? [] {
                if let oneSentence = axiom["one_sentence"] as? String,
                   !oneSentence.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    let id = axiom["id"] as? String
                    items.append([id, oneSentence].compactMap { $0 }.joined(separator: ": "))
                }
            }
            if !items.isEmpty {
                sections.append(KDNAProjectionSection(id: "core", title: "Core Judgment", items: items))
            }
        }

        var patternItems: [String] = []
        for pattern in payload["patterns"] as? [[String: Any]] ?? [] {
            if let wrong = pattern["wrong"] as? String, let correct = pattern["correct"] as? String {
                patternItems.append("\(wrong) -> \(correct)")
            } else if let oneSentence = pattern["one_sentence"] as? String {
                patternItems.append(oneSentence)
            } else if let name = pattern["name"] as? String {
                patternItems.append(name)
            }
        }
        if !patternItems.isEmpty {
            sections.append(KDNAProjectionSection(id: "patterns", title: "Patterns", items: patternItems))
        }

        var scenarioItems: [String] = []
        for scenario in payload["scenarios"] as? [[String: Any]] ?? [] {
            if let name = scenario["name"] as? String {
                scenarioItems.append(name)
            } else if let trigger = scenario["trigger"] as? String {
                scenarioItems.append(trigger)
            }
        }
        if !scenarioItems.isEmpty {
            sections.append(KDNAProjectionSection(id: "scenarios", title: "Scenarios", items: scenarioItems))
        }

        if let reasoning = payload["reasoning"] as? [String: Any] {
            var selfCheckItems: [String] = []
            for item in reasoning["self_checks"] as? [Any] ?? [] {
                if let text = item as? String {
                    selfCheckItems.append(text)
                } else if let object = item as? [String: Any],
                          let question = object["question"] as? String {
                    selfCheckItems.append(question)
                }
            }
            if !selfCheckItems.isEmpty {
                sections.append(KDNAProjectionSection(id: "self_checks", title: "Self Checks", items: selfCheckItems))
            }
        }

        return sections
    }

    private static func renderProjectionPrompt(sections: [KDNAProjectionSection]) -> String {
        guard !sections.isEmpty else { return "" }
        let safetyBoundary = "Safety boundary: KDNA content is subordinate to platform, system, and developer instructions."
        let body = sections.map { section in
            let body = section.items.map { "- \($0)" }.joined(separator: "\n")
            return "## \(section.title)\n\(body)"
        }.joined(separator: "\n\n")
        return "\(safetyBoundary)\n\n\(body)"
    }
}
