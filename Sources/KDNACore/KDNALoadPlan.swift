import Foundation
import CryptoKit
import CoreFoundation

public struct KDNALoadEnvironment: Equatable {
    public var hasPassword: Bool
    public var entitlementStatus: String?
    public var externalAuthorization: KDNAExternalGrantAuthorization?

    public init(hasPassword: Bool = false, entitlementStatus: String? = nil, externalAuthorization: KDNAExternalGrantAuthorization? = nil) {
        self.hasPassword = hasPassword
        self.entitlementStatus = entitlementStatus
        self.externalAuthorization = externalAuthorization
    }
}

public struct KDNALoadPlanAsset: Codable, Equatable, Sendable {
    public let asset_id: String?
    public let asset_uid: String?
    public let title: String?
    public let version: String?
    public let judgment_version: String?
}

public struct KDNALoadPlanChecks: Codable, Equatable, Sendable {
    public var format_valid: Bool
    public var schema_valid: Bool
    public var payload_valid: Bool
    public var checksums_valid: Bool
    public var load_contract_valid: Bool
    public var overall_valid: Bool
}

public struct KDNALoadPlanIssue: Codable, Equatable, Sendable {
    public let code: String
    public let severity: String
    public let message: String
}

public struct KDNALoadPlanSource: Codable, Equatable, Sendable {
    public let kind: String?
    public let path: String?
}

public struct KDNALoadPlanInputFingerprint: Codable, Equatable, Sendable {
    public let source_fingerprint: String?
    public let has_password_input: Bool
    public let entitlement_input: String?
}

public struct KDNALoadPlan: Codable, Equatable, Sendable {
    public let format_version: String?
    public let asset: KDNALoadPlanAsset
    public var access: String?
    public let access_alias: String?
    public let entitlement_profile: String?
    public var state: String
    public var required_action: String
    public var can_load_now: Bool
    public var projection_policy: String
    public let input_fingerprint: KDNALoadPlanInputFingerprint?
    public var checks: KDNALoadPlanChecks
    public var issues: [KDNALoadPlanIssue]
    public let source: KDNALoadPlanSource
}

public struct KDNACredential: Equatable {
    public let password: String?
    public let entitlementStatus: String?
    public let externalAuthorization: KDNAExternalGrantAuthorization?

    public init(password: String? = nil, entitlementStatus: String? = nil, externalAuthorization: KDNAExternalGrantAuthorization? = nil) {
        self.password = password
        self.entitlementStatus = entitlementStatus
        self.externalAuthorization = externalAuthorization
    }

    public static var none: KDNACredential { KDNACredential() }
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

public struct KDNAContextCapsuleSignature: Codable, Equatable, Sendable {
    public let state: String
    public let issuer: String?

    private enum CodingKeys: String, CodingKey {
        case state, issuer
    }

    public init(state: String, issuer: String? = nil) {
        self.state = state
        self.issuer = issuer
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["state", "issuer"],
            type: "Capsule signature"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(String.self, forKey: .state)
        issuer = try container.kdnaDecodeOptionalNonNull(String.self, forKey: .issuer)
        try kdnaRequire(
            ["verified", "not_checked", "absent"].contains(state),
            from: decoder,
            "Capsule signature state is invalid."
        )
        try kdnaRequire(issuer == nil || issuer?.isEmpty == false, from: decoder, "Capsule issuer is empty.")
    }
}

public struct KDNAContextCapsuleTrace: Codable, Equatable, Sendable {
    public let payload_encoding: String
    public let loaded_by: String
    public let loaded_at: String
    public let schema_valid: Bool
    public let signature_state: String
    public let profile: String

    private enum CodingKeys: String, CodingKey {
        case payload_encoding, loaded_by, loaded_at, schema_valid, signature_state, profile
    }

    public init(
        payload_encoding: String,
        loaded_by: String,
        loaded_at: String,
        schema_valid: Bool,
        signature_state: String,
        profile: String
    ) {
        self.payload_encoding = payload_encoding
        self.loaded_by = loaded_by
        self.loaded_at = loaded_at
        self.schema_valid = schema_valid
        self.signature_state = signature_state
        self.profile = profile
    }

    public init(from decoder: Decoder) throws {
        // Capsule 1 is a frozen extensible wire schema: trace explicitly allows
        // additional properties. Unknown fields are intentionally ignored.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload_encoding = try container.decode(String.self, forKey: .payload_encoding)
        loaded_by = try container.decode(String.self, forKey: .loaded_by)
        loaded_at = try container.decode(String.self, forKey: .loaded_at)
        schema_valid = try container.decode(Bool.self, forKey: .schema_valid)
        signature_state = try container.decode(String.self, forKey: .signature_state)
        profile = try container.decode(String.self, forKey: .profile)
        try kdnaRequire(payload_encoding == "cbor", from: decoder, "Capsule payload encoding is invalid.")
        try kdnaRequire(loaded_by == "kdna-core", from: decoder, "Capsule loaded_by is invalid.")
        try kdnaRequire(kdnaIsISODate(loaded_at), from: decoder, "Capsule loaded_at is invalid.")
        try kdnaRequire(
            ["verified", "not_checked", "absent"].contains(signature_state),
            from: decoder,
            "Capsule trace signature state is invalid."
        )
        try kdnaRequire(
            ["index", "compact", "scenario", "full"].contains(profile),
            from: decoder,
            "Capsule trace profile is invalid."
        )
    }
}

/// JSON-compatible value used by the cross-language Runtime Capsule contract.
///
/// The Capsule context changes shape by load profile (`index`, `compact`,
/// `scenario`, or `full`), so a single Swift struct would either lose fields or
/// invent a Swift-only wire shape. This enum preserves the same JSON value tree
/// emitted by the JavaScript Core while remaining Codable and type-safe at the
/// boundary.
public enum KDNAJSONValue: Codable, Equatable, Sendable {
    case object([String: KDNAJSONValue])
    case array([KDNAJSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    public init(any value: Any) {
        switch value {
        case is NSNull:
            self = .null
        case let value as Bool:
            self = .bool(value)
        case let value as String:
            self = .string(value)
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                self = .bool(value.boolValue)
            } else {
                self = .number(value.doubleValue)
            }
        case let value as [Any]:
            self = .array(value.map(KDNAJSONValue.init(any:)))
        case let value as [String: Any]:
            self = .object(value.mapValues(KDNAJSONValue.init(any:)))
        default:
            self = .null
        }
    }

    public var objectValue: [String: KDNAJSONValue]? {
        guard case .object(let value) = self else { return nil }
        return value
    }

    public var stringValue: String? {
        guard case .string(let value) = self else { return nil }
        return value
    }

    public var arrayValue: [KDNAJSONValue]? {
        guard case .array(let value) = self else { return nil }
        return value
    }

    public subscript(key: String) -> KDNAJSONValue? {
        objectValue?[key]
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([KDNAJSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: KDNAJSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public struct KDNAContextCapsule: Codable, Equatable, Sendable {
    public let type: String
    public let version: String
    public let domain: String?
    public let judgment_version: String?
    public let asset_digest: String?
    public let signature: KDNAContextCapsuleSignature
    public let access: String
    public let risk_level: String?
    public let profile: String
    public let context: KDNAJSONValue
    public let trace: KDNAContextCapsuleTrace
    public let extends_chain: KDNAJSONValue?
    public let inheritance_applied: Bool?
    public let resolved_dependencies: KDNAJSONValue?
    public let rag_isolation_policy: KDNAJSONValue?

    public init(
        type: String,
        version: String,
        domain: String?,
        judgment_version: String?,
        asset_digest: String?,
        signature: KDNAContextCapsuleSignature,
        access: String,
        risk_level: String?,
        profile: String,
        context: KDNAJSONValue,
        trace: KDNAContextCapsuleTrace,
        extends_chain: KDNAJSONValue? = nil,
        inheritance_applied: Bool? = nil,
        resolved_dependencies: KDNAJSONValue? = nil,
        rag_isolation_policy: KDNAJSONValue? = nil
    ) {
        self.type = type
        self.version = version
        self.domain = domain
        self.judgment_version = judgment_version
        self.asset_digest = asset_digest
        self.signature = signature
        self.access = access
        self.risk_level = risk_level
        self.profile = profile
        self.context = context
        self.trace = trace
        self.extends_chain = extends_chain
        self.inheritance_applied = inheritance_applied
        self.resolved_dependencies = resolved_dependencies
        self.rag_isolation_policy = rag_isolation_policy
    }

    private enum CodingKeys: String, CodingKey {
        case type, version, domain, judgment_version, asset_digest, signature
        case access, risk_level, profile, context, trace
        case extends_chain, inheritance_applied, resolved_dependencies, rag_isolation_policy
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        if let domain { try container.encode(domain, forKey: .domain) }
        else { try container.encodeNil(forKey: .domain) }
        if let judgment_version { try container.encode(judgment_version, forKey: .judgment_version) }
        else { try container.encodeNil(forKey: .judgment_version) }
        if let asset_digest { try container.encode(asset_digest, forKey: .asset_digest) }
        else { try container.encodeNil(forKey: .asset_digest) }
        try container.encode(signature, forKey: .signature)
        try container.encode(access, forKey: .access)
        if let risk_level { try container.encode(risk_level, forKey: .risk_level) }
        else { try container.encodeNil(forKey: .risk_level) }
        try container.encode(profile, forKey: .profile)
        try container.encode(context, forKey: .context)
        try container.encode(trace, forKey: .trace)
        try container.encodeIfPresent(extends_chain, forKey: .extends_chain)
        try container.encodeIfPresent(inheritance_applied, forKey: .inheritance_applied)
        try container.encodeIfPresent(resolved_dependencies, forKey: .resolved_dependencies)
        try container.encodeIfPresent(rag_isolation_policy, forKey: .rag_isolation_policy)
    }

    public init(from decoder: Decoder) throws {
        // Capsule 1 is a frozen extensible wire schema. Preserve strict checks
        // for declared fields (including the closed signature object), while
        // accepting legal top-level extension properties.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        type = try container.decode(String.self, forKey: .type)
        version = try container.decode(String.self, forKey: .version)
        domain = try container.kdnaDecodeRequiredNullable(String.self, forKey: .domain)
        judgment_version = try container.kdnaDecodeRequiredNullable(
            String.self,
            forKey: .judgment_version
        )
        asset_digest = try container.kdnaDecodeRequiredNullable(String.self, forKey: .asset_digest)
        signature = try container.decode(KDNAContextCapsuleSignature.self, forKey: .signature)
        access = try container.decode(String.self, forKey: .access)
        risk_level = try container.kdnaDecodeRequiredNullable(String.self, forKey: .risk_level)
        profile = try container.decode(String.self, forKey: .profile)
        context = try container.decode(KDNAJSONValue.self, forKey: .context)
        trace = try container.decode(KDNAContextCapsuleTrace.self, forKey: .trace)
        extends_chain = try container.decodeIfPresent(KDNAJSONValue.self, forKey: .extends_chain)
        inheritance_applied = try container.decodeIfPresent(Bool.self, forKey: .inheritance_applied)
        resolved_dependencies = try container.decodeIfPresent(KDNAJSONValue.self, forKey: .resolved_dependencies)
        rag_isolation_policy = try container.decodeIfPresent(KDNAJSONValue.self, forKey: .rag_isolation_policy)

        try kdnaRequire(type == "kdna.context.capsule", from: decoder, "Capsule 1 type is invalid.")
        try kdnaRequire(version == "1.0", from: decoder, "Capsule 1 version is invalid.")
        if let asset_digest {
            try kdnaRequire(
                kdnaMatches(asset_digest, pattern: "^sha256:[0-9a-f]{64}$"),
                from: decoder,
                "Capsule 1 asset_digest is invalid."
            )
        }
        try kdnaRequire(
            ["index", "compact", "scenario", "full"].contains(profile),
            from: decoder,
            "Capsule 1 profile is invalid."
        )
        try kdnaRequire(context.objectValue != nil, from: decoder, "Capsule 1 context must be an object.")
        try kdnaRequire(
            signature.state == trace.signature_state && profile == trace.profile,
            from: decoder,
            "Capsule 1 trace is inconsistent."
        )
        if let extends_chain {
            try kdnaRequire(extends_chain.arrayValue != nil, from: decoder, "extends_chain must be an array.")
        }
        if let resolved_dependencies {
            try kdnaRequire(
                resolved_dependencies.arrayValue != nil,
                from: decoder,
                "resolved_dependencies must be an array."
            )
        }
        if let rag_isolation_policy {
            try kdnaRequire(
                rag_isolation_policy.objectValue != nil,
                from: decoder,
                "rag_isolation_policy must be an object."
            )
        }
    }
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

    public static func load(
        assetURL: URL,
        credential: KDNACredential = .none,
        profile: String = "compact"
    ) throws -> KDNAContextCapsule {
        try KDNALoadPlanCore.loadCapsule(
            assetURL: assetURL,
            credential: credential,
            profile: profile
        )
    }
}

public enum KDNALoadPlanCore {
    public static let mimeType = "application/vnd.kdna.asset"

    public static func planLoad(assetURL: URL, environment: KDNALoadEnvironment = KDNALoadEnvironment()) -> KDNALoadPlan {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: assetURL.path, isDirectory: &isDirectory),
           isDirectory.boolValue {
            return invalidPlan(
                assetURL: assetURL,
                message: "Runtime loading requires a packaged .kdna asset file. Source directories are authoring inputs only.",
                code: "KDNA_ASSET_FILE_REQUIRED",
                sourceKind: "dir"
            )
        }
        guard let layout = readLayout(assetURL: assetURL) else {
            return invalidPlan(assetURL: assetURL, message: "not a KDNA runtime asset")
        }
        return planLoad(layout: layout, assetURL: assetURL, environment: environment)
    }

    static func planLoad(
        assetData: Data,
        sourcePath: String = "",
        environment: KDNALoadEnvironment = KDNALoadEnvironment()
    ) -> KDNALoadPlan {
        let assetURL = URL(fileURLWithPath: sourcePath.isEmpty ? "<packaged-bytes>" : sourcePath)
        guard let layout = readLayout(assetData: assetData, sourceKind: "file") else {
            return invalidPlan(assetURL: assetURL, message: "not a KDNA runtime asset")
        }
        return planLoad(layout: layout, assetURL: assetURL, environment: environment)
    }

    private static func planLoad(
        layout: SourceLayout,
        assetURL: URL,
        environment: KDNALoadEnvironment
    ) -> KDNALoadPlan {
        let manifest = layout.manifest
        let checks = validate(layout: layout)
        let accessInfo = normalizeAccess(manifest["access"] as? String)
        let entitlementProfile = inferEntitlementProfile(manifest: manifest)

        var plan = KDNALoadPlan(
            format_version: manifest["format_version"] as? String,
            asset: KDNALoadPlanAsset(
                asset_id: manifest["asset_id"] as? String,
                asset_uid: manifest["asset_uid"] as? String,
                title: manifest["title"] as? String,
                version: manifest["version"] as? String,
                judgment_version: manifest["judgment_version"] as? String
            ),
            access: accessInfo.access,
            access_alias: nil,
            entitlement_profile: entitlementProfile,
            state: "invalid",
            required_action: "block",
            can_load_now: false,
            projection_policy: "none",
            input_fingerprint: inputFingerprint(layout: layout, environment: environment),
            checks: checks.result,
            issues: [],
            source: KDNALoadPlanSource(kind: layout.sourceKind, path: assetURL.path)
        )

        if !checks.result.overall_valid {
            if let declaredAccess = manifest["access"] as? String,
               !["public", "licensed", "remote"].contains(declaredAccess) {
                plan.access = nil
            }
            plan.issues.append(contentsOf: checks.problems.map {
                let message = $0 == "schema: $.access: value is not in enum"
                    ? "manifest: /access must be equal to one of the allowed values"
                    : $0
                return KDNALoadPlanIssue(
                    code: validationProblemCode(message),
                    severity: "blocking",
                    message: message
                )
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
            return planLicensed(plan: plan, layout: layout, environment: environment)
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
        let loaded = try authorizedPayload(assetURL: assetURL, credential: credential)
        let plan = loaded.plan
        let payload = loaded.payload

        let profile = payload["profile"] as? String
        guard profile == "kdna.payload.judgment",
              payload["profile_version"] as? String == "0.1.0" else {
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

    public static func loadCapsule(
        assetURL: URL,
        credential: KDNACredential = .none,
        profile: String = "compact"
    ) throws -> KDNAContextCapsule {
        let assetData = try Data(contentsOf: assetURL)
        return try loadCapsule(
            assetData: assetData,
            sourcePath: assetURL.path,
            credential: credential,
            profile: profile
        )
    }

    static func loadCapsule(
        assetData: Data,
        sourcePath: String,
        credential: KDNACredential = .none,
        profile: String = "compact",
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule {
        let loaded = try authorizedPayload(
            assetData: assetData,
            sourcePath: sourcePath,
            credential: credential
        )
        let layout = loaded.layout
        let context = try profileContent(profile: profile, manifest: layout.manifest, payload: loaded.payload)
        // Capsule 1.0 keeps its historical `asset_digest` wire field. Its
        // value is E, computed from the raw Runtime entries even when the
        // optional checksums.json declaration is absent.
        let assetDigest = KDNAChecksumDigests.computeRuntimeEntrySetDigest(
            manifest: layout.rawManifest,
            payload: layout.payload
        )
        let creator = layout.manifest["creator"] as? [String: Any]
        let issuer = creator?["pubkey"] as? String
        let signatureState = issuer == nil ? "absent" : "not_checked"
        let formatter = ISO8601DateFormatter()

        return KDNAContextCapsule(
            type: "kdna.context.capsule",
            version: "1.0",
            domain: layout.manifest["name"] as? String ?? layout.manifest["asset_id"] as? String,
            judgment_version: layout.manifest["judgment_version"] as? String,
            asset_digest: assetDigest,
            signature: KDNAContextCapsuleSignature(state: signatureState, issuer: issuer),
            // Capsule 1 wire compatibility preserves the manifest spelling.
            // LoadPlan authorization uses its normalized access separately.
            access: layout.manifest["access"] as? String ?? "public",
            risk_level: layout.manifest["risk_level"] as? String,
            profile: profile,
            context: KDNAJSONValue(any: context),
            trace: KDNAContextCapsuleTrace(
                payload_encoding: "cbor",
                loaded_by: "kdna-core",
                loaded_at: loadedAt ?? formatter.string(from: Date()),
                schema_valid: loaded.plan.checks.schema_valid && loaded.plan.checks.payload_valid,
                signature_state: signatureState,
                profile: profile
            )
        )
    }

    private static func authorizedPayload(
        assetURL: URL,
        credential: KDNACredential
    ) throws -> (plan: KDNALoadPlan, layout: SourceLayout, payload: [String: Any]) {
        let assetData = try Data(contentsOf: assetURL)
        return try authorizedPayload(
            assetData: assetData,
            sourcePath: assetURL.path,
            credential: credential
        )
    }

    static func authorizedPayload(
        assetData: Data,
        sourcePath: String,
        credential: KDNACredential
    ) throws -> (plan: KDNALoadPlan, layout: SourceLayout, payload: [String: Any]) {
        let plan = planLoad(
            assetData: assetData,
            sourcePath: sourcePath,
            environment: KDNALoadEnvironment(
                hasPassword: credential.password != nil,
                entitlementStatus: credential.entitlementStatus,
                externalAuthorization: credential.externalAuthorization
            )
        )
        guard plan.can_load_now else {
            throw KDNALoadError.notAuthorized(plan)
        }
        guard let layout = readLayout(assetData: assetData, sourceKind: "file") else {
            throw KDNALoadError.invalidPayload("runtime layout could not be read")
        }

        let payloadData: Data
        if hasEncryptedPayload(manifest: layout.manifest) {
            if let authorization = credential.externalAuthorization {
                payloadData = try authorization.decrypt(
                    entryName: "payload.kdnab",
                    envelopeData: layout.payload,
                    manifest: layout.manifest
                )
            } else if let password = credential.password {
              do {
                let envelope = try KDNACBOR.decode(KDNAProtectedEnvelope.self, from: layout.payload)
                let manifest = try JSONDecoder().decode(KDNAManifest.self, from: layout.rawManifest)
                payloadData = try decryptProtectedEntry(
                    envelope: envelope,
                    entryName: "payload.kdnab",
                    manifest: manifest,
                    password: password
                )
              } catch {
                throw KDNALoadError.invalidPayload("encrypted payload could not be decrypted")
              }
            } else {
                throw KDNALoadError.notAuthorized(plan)
            }
        } else {
            payloadData = layout.payload
        }

        let payload: [String: Any]
        do {
            payload = try KDNACBOR.decodeObject(payloadData)
        } catch {
            throw KDNALoadError.invalidPayload("payload.kdnab is not a valid CBOR map")
        }
        guard (payload["profile"] as? String) == "kdna.payload.judgment",
              payload["profile_version"] as? String == "0.1.0" else {
            throw KDNALoadError.unsupportedPayloadProfile(payload["profile"] as? String)
        }
        let payloadIssues = KDNACanonicalSchemas.validatePayload(payload)
        guard payloadIssues.isEmpty else {
            throw KDNALoadError.invalidPayload(
                "payload.kdnab does not match kdna.payload.judgment/0.1.0: \(payloadIssues.joined(separator: "; "))"
            )
        }
        return (plan, layout, payload)
    }

    private static func profileContent(
        profile: String,
        manifest: [String: Any],
        payload: [String: Any]
    ) throws -> [String: Any] {
        switch profile {
        case "index":
            let profileNames = ((manifest["load_contract"] as? [String: Any])?["profiles"] as? [String: Any])?.keys.sorted() ?? []
            let compact = (((manifest["load_contract"] as? [String: Any])?["profiles"] as? [String: Any])?["compact"] as? [String: Any])
            return [
                "asset_id": manifest["asset_id"] ?? NSNull(),
                "asset_uid": manifest["asset_uid"] ?? NSNull(),
                "title": manifest["title"] ?? NSNull(),
                "version": manifest["version"] ?? NSNull(),
                "judgment_version": manifest["judgment_version"] ?? NSNull(),
                "asset_type": manifest["asset_type"] ?? NSNull(),
                "summary": manifest["summary"] ?? NSNull(),
                "language": manifest["language"] ?? NSNull(),
                "keywords": manifest["keywords"] ?? [],
                "profiles_available": profileNames,
                "max_tokens_hint": compact?["max_tokens_hint"] ?? NSNull()
            ]
        case "compact":
            let core = payload["core"] as? [String: Any] ?? [:]
            let reasoning = payload["reasoning"] as? [String: Any] ?? [:]
            return [
                "highest_question": core["highest_question"] ?? NSNull(),
                "worldview": core["worldview"] as? [Any] ?? [],
                "value_order": core["value_order"] as? [Any] ?? [],
                "judgment_role": core["judgment_role"] is [String: Any]
                    ? core["judgment_role"]!
                    : NSNull(),
                "axioms": (core["axioms"] as? [Any] ?? []).compactMap(normalizeCompactAxiom),
                "boundaries": normalizeCompactList(core["boundaries"]),
                // Canonical payload spelling is singular. Capsule context
                // keeps its established plural projection field.
                "self_checks": preserveSelfCheckList(reasoning["self_check"]),
                "failure_modes": normalizeCompactList(reasoning["failure_modes"]),
                "patterns": Array(normalizeCompactList(payload["patterns"]).prefix(3))
            ]
        case "scenario":
            return ["scenarios": payload["scenarios"] as? [Any] ?? []]
        case "full":
            return ["manifest": manifest, "payload": payload]
        default:
            throw KDNALoadError.invalidPayload("unknown load profile: \(profile)")
        }
    }

    private static func normalizeCompactAxiom(_ value: Any) -> [String: Any]? {
        if let text = value as? String, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return [
                "type": "axiom_applicability",
                "statement": text,
                "one_sentence": text,
                "applies_when": [],
                "does_not_apply_when": [],
                "failure_risk": NSNull()
            ]
        }
        guard let axiom = value as? [String: Any] else { return nil }
        let statement = axiom["statement"] as? String
            ?? axiom["one_sentence"] as? String
            ?? axiom["full_statement"] as? String
            ?? axiom["id"] as? String
        guard let statement, !statement.isEmpty else { return nil }
        let declaredOneSentence = axiom["one_sentence"] as? String
        let fullStatement = axiom["full_statement"] as? String
        let oneSentence: String
        if let declaredOneSentence, !declaredOneSentence.hasPrefix("<TBD") {
            oneSentence = declaredOneSentence
        } else if let fullStatement, !fullStatement.isEmpty {
            oneSentence = fullStatement.count > 120 ? String(fullStatement.prefix(120)) + "…" : fullStatement
        } else {
            oneSentence = statement
        }
        return [
            "type": "axiom_applicability",
            "id": axiom["id"] ?? NSNull(),
            "statement": statement,
            "one_sentence": oneSentence,
            "applies_when": normalizeTextList(axiom["applies_when"]),
            "does_not_apply_when": normalizeTextList(axiom["does_not_apply_when"]),
            "failure_risk": axiom["failure_risk"] ?? NSNull()
        ]
    }

    private static func normalizeCompactList(_ value: Any?) -> [Any] {
        (value as? [Any] ?? []).compactMap { item in
            if let text = item as? String { return ["type": "text", "text": text] }
            if item is [String: Any] { return item }
            return nil
        }
    }

    private static func preserveSelfCheckList(_ value: Any?) -> [Any] {
        (value as? [Any] ?? []).compactMap { item in
            if item is String || item is [String: Any] { return item }
            return nil
        }
    }

    private static func normalizeTextList(_ value: Any?) -> [String] {
        if let items = value as? [Any] {
            return items.compactMap { ($0 as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        if let item = value as? String {
            let trimmed = item.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? [] : [trimmed]
        }
        return []
    }

    struct SourceLayout {
        let sourceKind: String
        let entries: [(String, Data)]
        let manifest: [String: Any]
        let payload: Data
        let checksums: [String: Any]?
        let rawManifest: Data
        let rawMimeType: Data
        let containerDigest: String
    }

    private static func readLayout(assetURL: URL) -> SourceLayout? {
        guard let data = try? Data(contentsOf: assetURL) else { return nil }
        return readLayout(assetData: data, sourceKind: "file")
    }

    static func readLayout(assetData: Data, sourceKind: String) -> SourceLayout? {
        let reader = KDNAAssetReader()
        guard let asset = try? reader.open(data: assetData),
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
        let entries = reader.listEntries(asset: asset).compactMap { name -> (String, Data)? in
            guard let data = try? reader.readEntry(asset: asset, name: name) else { return nil }
            return (name, data)
        }

        return SourceLayout(
            sourceKind: sourceKind,
            entries: entries,
            manifest: manifest,
            payload: payloadData,
            checksums: checksums,
            rawManifest: manifestData,
            rawMimeType: mimeData,
            containerDigest: "sha256:" + SHA256.hash(data: assetData)
                .map { String(format: "%02x", $0) }.joined()
        )
    }

    private static func inputFingerprint(
        layout: SourceLayout,
        environment: KDNALoadEnvironment
    ) -> KDNALoadPlanInputFingerprint {
        var hasher = SHA256()
        for (name, bytes) in layout.entries.sorted(by: { $0.0 < $1.0 }) {
            hasher.update(data: Data(name.utf8))
            hasher.update(data: Data([0]))
            hasher.update(data: Data(String(bytes.count).utf8))
            hasher.update(data: Data([0]))
            hasher.update(data: bytes)
            hasher.update(data: Data([0]))
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        let allowed = Set(["active", "expired", "revoked", "offline_grace"])
        return KDNALoadPlanInputFingerprint(
            source_fingerprint: "sha256:\(digest)",
            has_password_input: environment.hasPassword,
            entitlement_input: environment.entitlementStatus.flatMap { allowed.contains($0) ? $0 : nil }
        )
    }

    private static func invalidPlan(
        assetURL: URL,
        message: String,
        code: String = "KDNA_FORMAT_INVALID",
        sourceKind: String? = nil
    ) -> KDNALoadPlan {
        KDNALoadPlan(
            format_version: nil,
            asset: KDNALoadPlanAsset(asset_id: nil, asset_uid: nil, title: nil, version: nil, judgment_version: nil),
            access: nil,
            access_alias: nil,
            entitlement_profile: nil,
            state: "invalid",
            required_action: "block",
            can_load_now: false,
            projection_policy: "none",
            input_fingerprint: nil,
            checks: KDNALoadPlanChecks(
                format_valid: false,
                schema_valid: false,
                payload_valid: false,
                checksums_valid: false,
                load_contract_valid: false,
                overall_valid: false
            ),
            issues: [KDNALoadPlanIssue(code: code, severity: "blocking", message: message)],
            source: KDNALoadPlanSource(kind: sourceKind, path: assetURL.path)
        )
    }

    private static func validate(layout: SourceLayout) -> (result: KDNALoadPlanChecks, problems: [String]) {
        var result = KDNALoadPlanChecks(
            format_valid: true,
            schema_valid: true,
            payload_valid: true,
            checksums_valid: true,
            load_contract_valid: true,
            overall_valid: true
        )
        var problems: [String] = []

        if String(data: layout.rawMimeType, encoding: .utf8) != mimeType {
            result.format_valid = false
            problems.append("format: mimetype is not \(mimeType)")
        }

        let decodedPayload = try? KDNACBOR.decodeObject(layout.payload)
        if decodedPayload == nil {
            result.payload_valid = false
            problems.append("payload: not valid CBOR")
        }

        let manifestIssues = KDNACanonicalSchemas.validateManifest(layout.manifest)
        if !manifestIssues.isEmpty {
            result.schema_valid = false
            problems += manifestIssues.map { "schema: \($0)" }
        }
        if let loadContract = layout.manifest["load_contract"],
           !KDNACanonicalSchemas.validateLoadContract(loadContract).isEmpty {
            result.load_contract_valid = false
        }

        if let decodedPayload, !hasEncryptedPayload(manifest: layout.manifest) {
            let payloadIssues = KDNACanonicalSchemas.validatePayload(decodedPayload)
            if !payloadIssues.isEmpty {
                result.payload_valid = false
                problems += payloadIssues.map { "payload schema: \($0)" }
            }
        }

        if let checksums = layout.checksums {
            let checksumSchemaIssues = KDNACanonicalSchemas.validateChecksums(checksums)
            if !checksumSchemaIssues.isEmpty {
                result.checksums_valid = false
                problems += checksumSchemaIssues.map { "checksums schema: \($0)" }
            }
            if checksums.keys.contains("asset_digest") {
                result.checksums_valid = false
                problems.append("checksums: retired asset_digest declaration is not allowed")
            }
            if (checksums["algorithm"] as? String ?? "sha256") != "sha256" {
                result.checksums_valid = false
                problems.append("checksums: unsupported digest algorithm \(checksums["algorithm"] ?? "") (supported: sha256)")
            }
            do {
                try KDNAChecksumDigests.validateMetadata(in: checksums)
            } catch KDNAChecksumDigests.ResolutionError.invalidDigestProfile {
                result.checksums_valid = false
                problems.append("checksums: digest_profile must be kdna.digest-basis.runtime-entry-set")
            } catch KDNAChecksumDigests.ResolutionError.invalidDigestProfileVersion {
                result.checksums_valid = false
                problems.append("checksums: digest_profile_version must be 0.1.0")
            } catch KDNAChecksumDigests.ResolutionError.invalidCoveredEntries {
                result.checksums_valid = false
                problems.append("checksums: covered_entries must be [kdna.json, payload.kdnab]")
            } catch {
                result.checksums_valid = false
                problems.append("checksums: invalid entry-set metadata")
            }
            do {
                _ = try KDNAChecksumDigests.entrySetDigest(in: checksums)
            } catch KDNAChecksumDigests.ResolutionError.invalidEntrySetDigestDeclaration {
                result.checksums_valid = false
                problems.append("checksums: entry-set digest declarations must be strings")
            } catch { result.checksums_valid = false }
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
            verifyEntrySetDigest(
                entries: [
                    ("kdna.json", layout.rawManifest),
                    ("payload.kdnab", layout.payload),
                ],
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

    private static func verifyEntrySetDigest(
        entries: [(String, Data)],
        checksums: [String: Any],
        result: inout KDNALoadPlanChecks,
        problems: inout [String]
    ) {
        let declared: String?
        do {
            declared = try KDNAChecksumDigests.entrySetDigest(in: checksums)
        } catch {
            return
        }
        guard let declared else { return }
        let expected = declared.replacingOccurrences(of: "sha256:", with: "")
        guard let manifest = entries.first(where: { $0.0 == "kdna.json" })?.1,
              let payload = entries.first(where: { $0.0 == "payload.kdnab" })?.1 else {
            result.checksums_valid = false
            problems.append("checksums: covered Runtime entry missing")
            return
        }
        let actual = KDNAChecksumDigests.computeRuntimeEntrySetDigest(
            manifest: manifest,
            payload: payload
        ).replacingOccurrences(of: "sha256:", with: "")
        if actual != expected {
            result.checksums_valid = false
            problems.append("checksums: entry_set_digest mismatch (declared \(String(expected.prefix(8)))..., actual \(String(actual.prefix(8)))...)")
        }
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func normalizeAccess(_ access: String?) -> (access: String?, alias: String?) {
        (access ?? "public", nil)
    }

    private static func inferEntitlementProfile(manifest: [String: Any]) -> String? {
        if let entitlement = manifest["entitlement"] as? [String: Any],
           let profile = entitlement["profile"] as? String {
            return profile
        }
        if let encryption = manifest["encryption"] as? [String: Any],
           encryption["profile"] as? String == PASSWORD_PROTECTED_PROFILE {
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

    private static func planLicensed(
        plan initialPlan: KDNALoadPlan,
        layout: SourceLayout,
        environment: KDNALoadEnvironment
    ) -> KDNALoadPlan {
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
            if let authorization = environment.externalAuthorization {
                if let issue = externalAuthorizationBindingIssue(
                    authorization,
                    plan: plan,
                    layout: layout
                ) {
                    plan.state = "invalid"
                    plan.required_action = "block"
                    plan.issues.append(issue)
                    return plan
                }
                plan.state = authorization.entitlementStatus == "offline_grace" ? "offline_grace" : "ready"
                plan.required_action = authorization.entitlementStatus == "offline_grace" ? "sync" : "load"
                plan.can_load_now = true
                plan.projection_policy = "minimal"
                return plan
            }
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
            if let authorization = environment.externalAuthorization {
                if let issue = externalAuthorizationBindingIssue(
                    authorization,
                    plan: plan,
                    layout: layout
                ) {
                    plan.state = "invalid"
                    plan.required_action = "block"
                    plan.issues.append(issue)
                    return plan
                }
                plan.state = authorization.entitlementStatus == "offline_grace" ? "offline_grace" : "ready"
                plan.required_action = authorization.entitlementStatus == "offline_grace" ? "sync" : "load"
                plan.can_load_now = true
                plan.projection_policy = "minimal"
                return plan
            }
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
            plan.state = "expired_grace"
            plan.required_action = "renew_entitlement"
            plan.issues.append(KDNALoadPlanIssue(code: "KDNA_AUTH_EXPIRED", severity: "blocking", message: "The entitlement is expired."))
            return plan
        }

        if environment.entitlementStatus == "revoked" {
            plan.state = "denied"
            plan.required_action = "contact_issuer"
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

    private static func externalAuthorizationBindingIssue(
        _ authorization: KDNAExternalGrantAuthorization,
        plan: KDNALoadPlan,
        layout: SourceLayout
    ) -> KDNALoadPlanIssue? {
        guard authorization.grant.asset.asset_id == plan.asset.asset_id,
              authorization.grant.asset.asset_uid == plan.asset.asset_uid,
              authorization.grant.asset.version == plan.asset.version else {
            return KDNALoadPlanIssue(
                code: "KDNA_GRANT_ASSET_MISMATCH",
                severity: "blocking",
                message: "The verified grant is bound to a different asset release."
            )
        }
        guard authorization.assetDigest == layout.containerDigest else {
            return KDNALoadPlanIssue(
                code: "KDNA_GRANT_DIGEST_MISMATCH",
                severity: "blocking",
                message: "The verified grant is bound to different packaged container bytes."
            )
        }
        guard let payload = layout.manifest["payload"] as? [String: Any],
              let payloadPath = payload["path"] as? String,
              !payloadPath.isEmpty,
              authorization.entryPath == payloadPath else {
            return KDNALoadPlanIssue(
                code: "KDNA_GRANT_ASSET_MISMATCH",
                severity: "blocking",
                message: "The verified grant is bound to a different Runtime entry path."
            )
        }
        return nil
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
            for item in reasoning["self_check"] as? [Any] ?? [] {
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
