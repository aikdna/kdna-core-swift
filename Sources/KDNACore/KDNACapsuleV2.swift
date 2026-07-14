import Foundation
import CryptoKit

/// Stable protocol error surfaced by the opt-in Capsule 2 APIs.
public struct KDNACapsule2Error: Error, LocalizedError, Equatable, Sendable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { "\(code): \(message)" }
}

public struct KDNAExpectedDigest: Equatable, Sendable {
    public let value: String
    public let source: String

    public init(value: String, source: String = "caller") {
        self.value = value
        self.source = source
    }
}

public struct KDNAExpectedDigests: Equatable, Sendable {
    public let asset: KDNAExpectedDigest?
    public let content: KDNAExpectedDigest?
    public let runtime_entry_set: KDNAExpectedDigest?

    public init(
        asset: KDNAExpectedDigest? = nil,
        content: KDNAExpectedDigest? = nil,
        runtime_entry_set: KDNAExpectedDigest? = nil
    ) {
        self.asset = asset
        self.content = content
        self.runtime_entry_set = runtime_entry_set
    }
}

public struct KDNADigestComparison: Codable, Equatable, Sendable {
    public let state: String
    public let against: String?
    public let expected: String?
    public let source: String?

    public init(state: String, against: String?, expected: String?, source: String?) {
        self.state = state
        self.against = against
        self.expected = expected
        self.source = source
    }

    private enum CodingKeys: String, CodingKey {
        case state, against, expected, source
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(state, forKey: .state)
        if let against { try container.encode(against, forKey: .against) }
        else { try container.encodeNil(forKey: .against) }
        if let expected { try container.encode(expected, forKey: .expected) }
        else { try container.encodeNil(forKey: .expected) }
        if let source { try container.encode(source, forKey: .source) }
        else { try container.encodeNil(forKey: .source) }
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["state", "against", "expected", "source"],
            type: "Digest comparison"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(String.self, forKey: .state)
        against = try container.kdnaDecodeRequiredNullable(String.self, forKey: .against)
        expected = try container.kdnaDecodeRequiredNullable(String.self, forKey: .expected)
        source = try container.kdnaDecodeRequiredNullable(String.self, forKey: .source)

        try kdnaRequire(
            ["matched", "mismatched", "not_compared", "unavailable"].contains(state),
            from: decoder,
            "Digest comparison state is invalid."
        )
        if state == "matched" || state == "mismatched" {
            try kdnaRequire(
                against.map {
                    ["external_expected", "manifest_declaration", "checksum_declaration"].contains($0)
                } == true,
                from: decoder,
                "Compared digest target is invalid."
            )
            try kdnaRequire(
                expected.map { kdnaMatches($0, pattern: "^sha256:[0-9a-f]{64}$") } == true,
                from: decoder,
                "Compared digest expectation is invalid."
            )
            try kdnaRequire(
                source.map {
                    [
                        "caller", "registry", "install_receipt", "lockfile",
                        "kdna.json.content_digest", "kdna.json.authoring.content_digest",
                        "checksums.json.entry_set_digest", "checksums.json.asset_digest",
                    ].contains($0)
                } == true,
                from: decoder,
                "Compared digest source is invalid."
            )
        } else {
            try kdnaRequire(
                against == nil && expected == nil && source == nil,
                from: decoder,
                "Non-compared digest evidence must contain explicit null metadata."
            )
        }
    }
}

public struct KDNADigestObservation: Codable, Equatable, Sendable {
    public let value: String?
    public let basis: String
    public let comparison: KDNADigestComparison

    public init(value: String?, basis: String, comparison: KDNADigestComparison) {
        self.value = value
        self.basis = basis
        self.comparison = comparison
    }

    private enum CodingKeys: String, CodingKey {
        case value, basis, comparison
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if let value { try container.encode(value, forKey: .value) }
        else { try container.encodeNil(forKey: .value) }
        try container.encode(basis, forKey: .basis)
        try container.encode(comparison, forKey: .comparison)
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["value", "basis", "comparison"],
            type: "Digest observation"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        value = try container.kdnaDecodeRequiredNullable(String.self, forKey: .value)
        basis = try container.decode(String.self, forKey: .basis)
        comparison = try container.decode(KDNADigestComparison.self, forKey: .comparison)
        if comparison.state == "unavailable" {
            try kdnaRequire(value == nil, from: decoder, "Unavailable digest observation must be null.")
        } else {
            try kdnaRequire(
                value.map { kdnaMatches($0, pattern: "^sha256:[0-9a-f]{64}$") } == true,
                from: decoder,
                "Digest observation value is invalid."
            )
        }
    }
}

public struct KDNADigestEvidence: Codable, Equatable, Sendable {
    public let profile: String
    public let asset: KDNADigestObservation
    public let content: KDNADigestObservation
    public let runtime_entry_set: KDNADigestObservation

    public init(
        profile: String,
        asset: KDNADigestObservation,
        content: KDNADigestObservation,
        runtime_entry_set: KDNADigestObservation
    ) {
        self.profile = profile
        self.asset = asset
        self.content = content
        self.runtime_entry_set = runtime_entry_set
    }

    private enum CodingKeys: String, CodingKey {
        case profile, asset, content, runtime_entry_set
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["profile", "asset", "content", "runtime_entry_set"],
            type: "Digest evidence"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        profile = try container.decode(String.self, forKey: .profile)
        asset = try container.decode(KDNADigestObservation.self, forKey: .asset)
        content = try container.decode(KDNADigestObservation.self, forKey: .content)
        runtime_entry_set = try container.decode(
            KDNADigestObservation.self,
            forKey: .runtime_entry_set
        )
        try kdnaRequire(
            profile == "kdna-capsule-digests-v1",
            from: decoder,
            "Digest evidence profile is invalid."
        )
        try kdnaRequire(asset.basis == "kdna-container-bytes-v1", from: decoder, "A basis is invalid.")
        try kdnaRequire(content.basis == "kdna-content-tree-v1", from: decoder, "C basis is invalid.")
        try kdnaRequire(
            runtime_entry_set.basis == "kdna-runtime-entry-set-v1",
            from: decoder,
            "E basis is invalid."
        )
    }
}

public struct KDNAContextCapsule2Asset: Codable, Equatable, Sendable {
    public let asset_id: String
    public let asset_uid: String
    public let version: String
    public let judgment_version: String

    public init(asset_id: String, asset_uid: String, version: String, judgment_version: String) {
        self.asset_id = asset_id
        self.asset_uid = asset_uid
        self.version = version
        self.judgment_version = judgment_version
    }

    private enum CodingKeys: String, CodingKey {
        case asset_id, asset_uid, version, judgment_version
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["asset_id", "asset_uid", "version", "judgment_version"],
            type: "Capsule 2 asset"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        asset_id = try container.decode(String.self, forKey: .asset_id)
        asset_uid = try container.decode(String.self, forKey: .asset_uid)
        version = try container.decode(String.self, forKey: .version)
        judgment_version = try container.decode(String.self, forKey: .judgment_version)
        try kdnaRequire(
            kdnaMatches(asset_id, pattern: "^[a-zA-Z][a-zA-Z0-9_-]*(:[a-zA-Z0-9_.-]+)+$"),
            from: decoder,
            "Capsule 2 asset_id is invalid."
        )
        try kdnaRequire(
            KDNAJSONFormats.isURI(asset_uid),
            from: decoder,
            "Capsule 2 asset_uid is invalid."
        )
        try kdnaRequire(
            kdnaMatches(version, pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+([+-].+)?$"),
            from: decoder,
            "Capsule 2 version is invalid."
        )
        try kdnaRequire(
            kdnaMatches(judgment_version, pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+([+-].+)?$"),
            from: decoder,
            "Capsule 2 judgment_version is invalid."
        )
    }
}

public struct KDNAContextCapsule2Trace: Codable, Equatable, Sendable {
    public let payload_encoding: String
    public let loaded_by: String
    public let loaded_at: String
    public let input_kind: String
    public let runtime_eligible: Bool
    public let schema_valid: Bool
    public let signature_state: String
    public let profile: String

    public init(
        payload_encoding: String,
        loaded_by: String,
        loaded_at: String,
        input_kind: String,
        runtime_eligible: Bool,
        schema_valid: Bool,
        signature_state: String,
        profile: String
    ) {
        self.payload_encoding = payload_encoding
        self.loaded_by = loaded_by
        self.loaded_at = loaded_at
        self.input_kind = input_kind
        self.runtime_eligible = runtime_eligible
        self.schema_valid = schema_valid
        self.signature_state = signature_state
        self.profile = profile
    }

    private enum CodingKeys: String, CodingKey {
        case payload_encoding, loaded_by, loaded_at, input_kind, runtime_eligible
        case schema_valid, signature_state, profile
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: [
                "payload_encoding", "loaded_by", "loaded_at", "input_kind",
                "runtime_eligible", "schema_valid", "signature_state", "profile",
            ],
            type: "Capsule 2 trace"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload_encoding = try container.decode(String.self, forKey: .payload_encoding)
        loaded_by = try container.decode(String.self, forKey: .loaded_by)
        loaded_at = try container.decode(String.self, forKey: .loaded_at)
        input_kind = try container.decode(String.self, forKey: .input_kind)
        runtime_eligible = try container.decode(Bool.self, forKey: .runtime_eligible)
        schema_valid = try container.decode(Bool.self, forKey: .schema_valid)
        signature_state = try container.decode(String.self, forKey: .signature_state)
        profile = try container.decode(String.self, forKey: .profile)
        try kdnaRequire(payload_encoding == "cbor", from: decoder, "Capsule 2 encoding is invalid.")
        try kdnaRequire(loaded_by == "kdna-core", from: decoder, "Capsule 2 loaded_by is invalid.")
        try kdnaRequire(kdnaIsISODate(loaded_at), from: decoder, "Capsule 2 loaded_at is invalid.")
        try kdnaRequire(
            ["packaged_file", "packaged_bytes"].contains(input_kind),
            from: decoder,
            "Capsule 2 input_kind is invalid."
        )
        try kdnaRequire(runtime_eligible, from: decoder, "Capsule 2 is not runtime eligible.")
        try kdnaRequire(schema_valid, from: decoder, "Capsule 2 schema_valid is false.")
        try kdnaRequire(
            ["verified", "not_checked", "absent"].contains(signature_state),
            from: decoder,
            "Capsule 2 signature state is invalid."
        )
        try kdnaRequire(
            ["index", "compact", "scenario", "full"].contains(profile),
            from: decoder,
            "Capsule 2 profile is invalid."
        )
    }
}

public struct KDNAContextCapsule1Extensions: Codable, Equatable, Sendable {
    public let extends_chain: KDNAJSONValue?
    public let inheritance_applied: Bool?
    public let resolved_dependencies: KDNAJSONValue?
    public let rag_isolation_policy: KDNAJSONValue?

    public init(
        extends_chain: KDNAJSONValue? = nil,
        inheritance_applied: Bool? = nil,
        resolved_dependencies: KDNAJSONValue? = nil,
        rag_isolation_policy: KDNAJSONValue? = nil
    ) {
        self.extends_chain = extends_chain
        self.inheritance_applied = inheritance_applied
        self.resolved_dependencies = resolved_dependencies
        self.rag_isolation_policy = rag_isolation_policy
    }

    private enum CodingKeys: String, CodingKey {
        case extends_chain, inheritance_applied, resolved_dependencies, rag_isolation_policy
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: [
                "extends_chain", "inheritance_applied", "resolved_dependencies",
                "rag_isolation_policy",
            ],
            type: "Capsule 1 extensions"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        extends_chain = try container.kdnaDecodeOptionalNonNull(
            KDNAJSONValue.self,
            forKey: .extends_chain
        )
        inheritance_applied = try container.kdnaDecodeOptionalNonNull(
            Bool.self,
            forKey: .inheritance_applied
        )
        resolved_dependencies = try container.kdnaDecodeOptionalNonNull(
            KDNAJSONValue.self,
            forKey: .resolved_dependencies
        )
        rag_isolation_policy = try container.kdnaDecodeOptionalNonNull(
            KDNAJSONValue.self,
            forKey: .rag_isolation_policy
        )
        try kdnaRequire(!isEmpty, from: decoder, "Capsule 1 extensions must not be empty.")
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

    var isEmpty: Bool {
        extends_chain == nil && inheritance_applied == nil &&
            resolved_dependencies == nil && rag_isolation_policy == nil
    }
}

public struct KDNAContextCapsule2Compatibility: Codable, Equatable, Sendable {
    public let capsule_1_domain: String?
    public let capsule_1_access: String?
    public let capsule_1_extensions: KDNAContextCapsule1Extensions?

    public init(
        capsule_1_domain: String? = nil,
        capsule_1_access: String? = nil,
        capsule_1_extensions: KDNAContextCapsule1Extensions? = nil
    ) {
        self.capsule_1_domain = capsule_1_domain
        self.capsule_1_access = capsule_1_access
        self.capsule_1_extensions = capsule_1_extensions
    }

    private enum CodingKeys: String, CodingKey {
        case capsule_1_domain, capsule_1_access, capsule_1_extensions
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: ["capsule_1_domain", "capsule_1_access", "capsule_1_extensions"],
            type: "Capsule 2 compatibility"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        capsule_1_domain = try container.kdnaDecodeOptionalNonNull(
            String.self,
            forKey: .capsule_1_domain
        )
        capsule_1_access = try container.kdnaDecodeOptionalNonNull(
            String.self,
            forKey: .capsule_1_access
        )
        capsule_1_extensions = try container.kdnaDecodeOptionalNonNull(
            KDNAContextCapsule1Extensions.self,
            forKey: .capsule_1_extensions
        )
        try kdnaRequire(!isEmpty, from: decoder, "Capsule 2 compatibility must not be empty.")
        try kdnaRequire(
            capsule_1_domain == nil || capsule_1_domain?.isEmpty == false,
            from: decoder,
            "Capsule 1 compatibility domain is empty."
        )
        if let capsule_1_access {
            try kdnaRequire(
                ["open", "protected", "runtime"].contains(capsule_1_access),
                from: decoder,
                "Capsule 1 compatibility access is invalid."
            )
        }
    }

    var isEmpty: Bool {
        capsule_1_domain == nil && capsule_1_access == nil && capsule_1_extensions == nil
    }
}

public struct KDNAContextCapsule2: Codable, Equatable, Sendable {
    public let type: String
    public let version: String
    public let asset: KDNAContextCapsule2Asset
    public let digests: KDNADigestEvidence
    public let signature: KDNAContextCapsuleSignature
    public let access: String
    public let risk_level: String?
    public let profile: String
    public let context: KDNAJSONValue
    public let trace: KDNAContextCapsule2Trace
    public let compatibility: KDNAContextCapsule2Compatibility?

    public init(
        type: String = "kdna.context.capsule",
        version: String = "2.0",
        asset: KDNAContextCapsule2Asset,
        digests: KDNADigestEvidence,
        signature: KDNAContextCapsuleSignature,
        access: String,
        risk_level: String?,
        profile: String,
        context: KDNAJSONValue,
        trace: KDNAContextCapsule2Trace,
        compatibility: KDNAContextCapsule2Compatibility? = nil
    ) {
        self.type = type
        self.version = version
        self.asset = asset
        self.digests = digests
        self.signature = signature
        self.access = access
        self.risk_level = risk_level
        self.profile = profile
        self.context = context
        self.trace = trace
        self.compatibility = compatibility
    }

    private enum CodingKeys: String, CodingKey {
        case type, version, asset, digests, signature, access, risk_level
        case profile, context, trace, compatibility
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(asset, forKey: .asset)
        try container.encode(digests, forKey: .digests)
        try container.encode(signature, forKey: .signature)
        try container.encode(access, forKey: .access)
        if let risk_level { try container.encode(risk_level, forKey: .risk_level) }
        else { try container.encodeNil(forKey: .risk_level) }
        try container.encode(profile, forKey: .profile)
        try container.encode(context, forKey: .context)
        try container.encode(trace, forKey: .trace)
        try container.encodeIfPresent(compatibility, forKey: .compatibility)
    }

    public init(from decoder: Decoder) throws {
        try kdnaRejectUnknownKeys(
            from: decoder,
            allowed: [
                "type", "version", "asset", "digests", "signature", "access",
                "risk_level", "profile", "context", "trace", "compatibility",
            ],
            type: "Capsule 2"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        type = try container.decode(String.self, forKey: .type)
        version = try container.decode(String.self, forKey: .version)
        asset = try container.decode(KDNAContextCapsule2Asset.self, forKey: .asset)
        digests = try container.decode(KDNADigestEvidence.self, forKey: .digests)
        signature = try container.decode(KDNAContextCapsuleSignature.self, forKey: .signature)
        access = try container.decode(String.self, forKey: .access)
        risk_level = try container.kdnaDecodeRequiredNullable(String.self, forKey: .risk_level)
        profile = try container.decode(String.self, forKey: .profile)
        context = try container.decode(KDNAJSONValue.self, forKey: .context)
        trace = try container.decode(KDNAContextCapsule2Trace.self, forKey: .trace)
        compatibility = try container.kdnaDecodeOptionalNonNull(
            KDNAContextCapsule2Compatibility.self,
            forKey: .compatibility
        )
        do {
            try KDNACapsuleV2.validateSuccessfulCapsule(
                self,
                code: "KDNA_CAPSULE_DECODING_INVALID"
            )
        } catch {
            throw DecodingError.dataCorrupted(DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: error.localizedDescription
            ))
        }
    }
}

/// Strict RFC 8785 canonicalization for Swift's JSON value tree.
///
/// This is intentionally separate from the historical content-digest
/// stableStringify helper: non-finite numbers are errors, never `null`.
public enum KDNAJCS {
    public static func canonicalString(_ value: KDNAJSONValue) throws -> String {
        try serialize(value)
    }

    public static func canonicalData(_ value: KDNAJSONValue) throws -> Data {
        Data(try canonicalString(value).utf8)
    }

    private static func serialize(_ value: KDNAJSONValue) throws -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .string(let value):
            return quote(value)
        case .number(let value):
            return try number(value)
        case .array(let values):
            return "[" + (try values.map(serialize)).joined(separator: ",") + "]"
        case .object(let object):
            let members = try object.keys.sorted(by: utf16Less).map { key in
                "\(quote(key)):\(try serialize(object[key]!))"
            }
            return "{" + members.joined(separator: ",") + "}"
        }
    }

    private static func quote(_ value: String) -> String {
        // Swift String contains Unicode scalar values, so unpaired UTF-16
        // surrogates cannot enter this API. JSONDecoder also rejects them.
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0A: result += "\\n"
            case 0x0C: result += "\\f"
            case 0x0D: result += "\\r"
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x00...0x1F: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        result += "\""
        return result
    }

    private static func number(_ value: Double) throws -> String {
        guard value.isFinite else {
            throw KDNACapsule2Error(
                code: "KDNA_JCS_NON_FINITE_NUMBER",
                message: "JCS input contains a non-finite number."
            )
        }
        if value == 0 { return "0" }

        // Swift's Double description is shortest-roundtrip. Normalize its
        // spelling to the ECMAScript thresholds required by RFC 8785.
        let raw = String(value).lowercased()
        guard let marker = raw.firstIndex(of: "e") else {
            return raw.hasSuffix(".0") ? String(raw.dropLast(2)) : raw
        }
        let mantissa = String(raw[..<marker])
        let exponentText = String(raw[raw.index(after: marker)...])
        guard let exponent = Int(exponentText) else {
            throw KDNACapsule2Error(
                code: "KDNA_JCS_NUMBER_SERIALIZATION_FAILED",
                message: "Swift emitted an unsupported floating-point representation."
            )
        }
        let magnitude = abs(value)
        if magnitude >= 1e-6 && magnitude < 1e21 {
            return expandScientific(mantissa: mantissa, exponent: exponent)
        }
        let normalized = mantissa.hasSuffix(".0") ? String(mantissa.dropLast(2)) : mantissa
        return "\(normalized)e\(exponent >= 0 ? "+" : "-")\(abs(exponent))"
    }

    private static func expandScientific(mantissa: String, exponent: Int) -> String {
        let negative = mantissa.hasPrefix("-")
        let unsigned = negative ? String(mantissa.dropFirst()) : mantissa
        let parts = unsigned.split(separator: ".", omittingEmptySubsequences: false)
        let integer = String(parts[0])
        let fraction = parts.count == 2 ? String(parts[1]) : ""
        let digits = integer + fraction
        let decimalPosition = integer.count + exponent
        let expanded: String
        if decimalPosition <= 0 {
            expanded = "0." + String(repeating: "0", count: -decimalPosition) + digits
        } else if decimalPosition >= digits.count {
            expanded = digits + String(repeating: "0", count: decimalPosition - digits.count)
        } else {
            let split = digits.index(digits.startIndex, offsetBy: decimalPosition)
            expanded = String(digits[..<split]) + "." + String(digits[split...])
        }
        return negative ? "-" + expanded : expanded
    }

    private static func utf16Less(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf16.lexicographicallyPrecedes(rhs.utf16)
    }
}

/// Opt-in Runtime Capsule 2 primitives. Existing Capsule 1 loading remains the
/// default KDNARuntime API.
public enum KDNACapsuleV2 {
    public static let digestProfile = "kdna-capsule-digests-v1"
    public static let deliveryDigestProfile = "kdna-capsule-jcs-v1"
    public static let assetBasis = "kdna-container-bytes-v1"
    public static let contentBasis = "kdna-content-tree-v1"
    public static let runtimeEntrySetBasis = "kdna-runtime-entry-set-v1"

    private static let sha256Pattern = try! NSRegularExpression(
        pattern: "^sha256:[0-9a-f]{64}$"
    )
    private static let assetIDPattern = try! NSRegularExpression(
        pattern: "^[a-zA-Z][a-zA-Z0-9_-]*(:[a-zA-Z0-9_.-]+)+$"
    )
    private static let versionPattern = try! NSRegularExpression(
        pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+([+-].+)?$"
    )
    private static let externalSources: Set<String> = [
        "caller", "registry", "install_receipt", "lockfile",
    ]
    private static let comparisonSources: Set<String> = externalSources.union([
        "kdna.json.content_digest",
        "kdna.json.authoring.content_digest",
        "checksums.json.entry_set_digest",
        "checksums.json.asset_digest",
    ])
    private static let comparisonTargets: Set<String> = [
        "external_expected", "manifest_declaration", "checksum_declaration",
    ]
    private static let accessAliases = [
        "open": "public",
        "protected": "licensed",
        "runtime": "remote",
    ]
    private static let profiles: Set<String> = ["index", "compact", "scenario", "full"]
    private static let signatureStates: Set<String> = ["verified", "not_checked", "absent"]

    public static func computeAssetDigest(_ bytes: Data) -> String {
        "sha256:" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    public static func computeRuntimeEntrySetDigest(
        manifest: Data,
        payload: Data
    ) -> String {
        KDNAChecksumDigests.computeRuntimeEntrySetDigest(manifest: manifest, payload: payload)
    }

    public static func computeDigestEvidence(
        assetData: Data,
        expected: KDNAExpectedDigests = KDNAExpectedDigests()
    ) throws -> KDNADigestEvidence {
        let reader = KDNAAssetReader()
        let asset: KDNAAsset
        do {
            asset = try reader.open(data: assetData)
        } catch {
            throw protocolError("KDNA_DIGEST_INPUT_INVALID", "Digest evidence requires packaged KDNA bytes.")
        }
        guard reader.hasEntry(asset: asset, name: "kdna.json"),
              reader.hasEntry(asset: asset, name: "payload.kdnab") else {
            throw protocolError(
                "KDNA_DIGEST_INPUT_INVALID",
                "Digest evidence requires kdna.json and payload.kdnab entries."
            )
        }

        let manifestData = try reader.readEntry(asset: asset, name: "kdna.json")
        let payloadData = try reader.readEntry(asset: asset, name: "payload.kdnab")
        let manifest = try jsonObject(manifestData, entry: "kdna.json")
        let checksums: [String: Any]?
        if reader.hasEntry(asset: asset, name: "checksums.json") {
            checksums = try jsonObject(
                reader.readEntry(asset: asset, name: "checksums.json"),
                entry: "checksums.json"
            )
        } else {
            checksums = nil
        }

        let observedAsset = computeAssetDigest(assetData)
        let observedContent: String
        do {
            observedContent = try KDNAContentDigest.computeValidated(asset: asset, reader: reader)
        } catch {
            throw protocolError("KDNA_DIGEST_INPUT_INVALID", error.localizedDescription)
        }
        let observedEntrySet = computeRuntimeEntrySetDigest(
            manifest: manifestData,
            payload: payloadData
        )
        let declaredContent = try contentDeclaration(manifest)
        let declaredEntrySet = try entrySetDeclaration(checksums)

        return KDNADigestEvidence(
            profile: digestProfile,
            asset: KDNADigestObservation(
                value: observedAsset,
                basis: assetBasis,
                comparison: try comparison(
                    observed: observedAsset,
                    expected: normalizeExternal(expected.asset),
                    against: "external_expected"
                )
            ),
            content: KDNADigestObservation(
                value: observedContent,
                basis: contentBasis,
                comparison: try comparisonWithDeclarationPriority(
                    observed: observedContent,
                    declared: declaredContent,
                    external: normalizeExternal(expected.content),
                    declarationTarget: "manifest_declaration"
                )
            ),
            runtime_entry_set: KDNADigestObservation(
                value: observedEntrySet,
                basis: runtimeEntrySetBasis,
                comparison: try comparisonWithDeclarationPriority(
                    observed: observedEntrySet,
                    declared: declaredEntrySet,
                    external: normalizeExternal(expected.runtime_entry_set),
                    declarationTarget: "checksum_declaration"
                )
            )
        )
    }

    public static func computeDigestEvidence(
        assetURL: URL,
        expected: KDNAExpectedDigests = KDNAExpectedDigests()
    ) throws -> KDNADigestEvidence {
        try computeDigestEvidence(assetData: Data(contentsOf: assetURL), expected: expected)
    }

    public static func computeDeliveryDigest(_ capsule: KDNAContextCapsule2) throws -> String {
        computeAssetDigest(try KDNAJCS.canonicalData(jsonValue(capsule)))
    }

    public static func load(
        assetData: Data,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule2 {
        let digests = try computeDigestEvidence(assetData: assetData, expected: expected)
        let capsule1 = try KDNALoadPlanCore.loadCapsule(
            assetData: assetData,
            sourcePath: "<packaged-bytes>",
            credential: credential,
            profile: profile,
            loadedAt: loadedAt
        )
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: assetData)
        guard let manifest = try reader.readManifest(asset: asset) else {
            throw protocolError("KDNA_CAPSULE_2_ASSET_INVALID", "Runtime manifest is missing.")
        }
        return try build(
            capsule1: capsule1,
            manifest: manifest,
            digests: digests,
            inputKind: "packaged_bytes",
            loadedAt: loadedAt
        )
    }

    public static func load(
        assetURL: URL,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule2 {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: assetURL.path, isDirectory: &isDirectory),
           isDirectory.boolValue {
            throw protocolError(
                "KDNA_ASSET_FILE_REQUIRED",
                "Runtime Capsule 2 requires final packaged KDNA bytes."
            )
        }
        let assetData: Data
        do {
            assetData = try Data(contentsOf: assetURL)
        } catch {
            throw protocolError(
                "KDNA_CAPSULE_2_INPUT_INVALID",
                "Cannot read packaged KDNA asset."
            )
        }
        let digests = try computeDigestEvidence(assetData: assetData, expected: expected)
        let capsule1 = try KDNALoadPlanCore.loadCapsule(
            assetData: assetData,
            sourcePath: assetURL.path,
            credential: credential,
            profile: profile,
            loadedAt: loadedAt
        )
        let reader = KDNAAssetReader()
        let asset = try reader.open(data: assetData, path: assetURL.path)
        guard let manifest = try reader.readManifest(asset: asset) else {
            throw protocolError("KDNA_CAPSULE_2_ASSET_INVALID", "Runtime manifest is missing.")
        }
        return try build(
            capsule1: capsule1,
            manifest: manifest,
            digests: digests,
            inputKind: "packaged_file",
            loadedAt: loadedAt
        )
    }

    public static func build(
        capsule1: KDNAContextCapsule,
        manifest: [String: Any],
        digests: KDNADigestEvidence,
        inputKind: String,
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule2 {
        try assertCapsule1Success(capsule1, code: "KDNA_CAPSULE_2_BUILD_INVALID")
        guard inputKind == "packaged_file" || inputKind == "packaged_bytes" else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 2 input_kind must identify packaged bytes."
            )
        }
        let assetID = try requiredManifestString(manifest, "asset_id")
        let assetUID = try requiredManifestString(manifest, "asset_uid")
        let version = try requiredManifestString(manifest, "version")
        let judgmentVersion = try requiredManifestString(manifest, "judgment_version")
        try assertSuccessfulEvidence(digests)

        let expectedDomain = manifest["name"] as? String ?? assetID
        guard capsule1.domain == expectedDomain else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 1 domain does not match the Runtime manifest identity."
            )
        }
        guard capsule1.judgment_version == judgmentVersion else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 1 judgment_version does not match the Runtime manifest."
            )
        }
        let expectedAccess = manifest["access"] as? String ?? "public"
        guard capsule1.access == expectedAccess else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 1 access does not match the Runtime manifest."
            )
        }
        guard capsule1.asset_digest == digests.runtime_entry_set.value else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 1 asset_digest does not match Runtime entry-set digest E."
            )
        }
        guard case .object = capsule1.context else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 1 context must be a JSON object."
            )
        }

        let timestamp = loadedAt ?? capsule1.trace.loaded_at
        guard KDNAJSONFormats.isDateTime(timestamp) else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Capsule 2 loaded_at must be an ISO date-time string."
            )
        }

        let extensions = KDNAContextCapsule1Extensions(
            extends_chain: capsule1.extends_chain,
            inheritance_applied: capsule1.inheritance_applied,
            resolved_dependencies: capsule1.resolved_dependencies,
            rag_isolation_policy: capsule1.rag_isolation_policy
        )
        let compatibility = KDNAContextCapsule2Compatibility(
            capsule_1_domain: capsule1.domain == assetID ? nil : capsule1.domain,
            capsule_1_access: accessAliases[capsule1.access] == nil ? nil : capsule1.access,
            capsule_1_extensions: extensions.isEmpty ? nil : extensions
        )

        let capsule = KDNAContextCapsule2(
            asset: KDNAContextCapsule2Asset(
                asset_id: assetID,
                asset_uid: assetUID,
                version: version,
                judgment_version: judgmentVersion
            ),
            digests: digests,
            signature: capsule1.signature,
            access: canonicalAccess(capsule1.access),
            risk_level: capsule1.risk_level,
            profile: capsule1.profile,
            context: capsule1.context,
            trace: KDNAContextCapsule2Trace(
                payload_encoding: capsule1.trace.payload_encoding,
                loaded_by: "kdna-core",
                loaded_at: timestamp,
                input_kind: inputKind,
                runtime_eligible: true,
                schema_valid: capsule1.trace.schema_valid,
                signature_state: capsule1.trace.signature_state,
                profile: capsule1.profile
            ),
            compatibility: compatibility.isEmpty ? nil : compatibility
        )
        try validateSuccessfulCapsule(capsule, code: "KDNA_CAPSULE_2_BUILD_INVALID")
        return capsule
    }

    public static func adaptToV1(_ capsule: KDNAContextCapsule2) throws -> KDNAContextCapsule {
        try validateSuccessfulCapsule(capsule, code: "KDNA_CAPSULE_ADAPTER_INPUT_INVALID")
        let domain = capsule.compatibility?.capsule_1_domain ?? capsule.asset.asset_id
        guard !domain.isEmpty else {
            throw protocolError(
                "KDNA_CAPSULE_ADAPTER_INPUT_INVALID",
                "Capsule 2 has no Capsule 1 domain mapping."
            )
        }
        let extensions = capsule.compatibility?.capsule_1_extensions
        let capsule1 = KDNAContextCapsule(
            type: "kdna.context.capsule",
            version: "1.0",
            domain: domain,
            judgment_version: capsule.asset.judgment_version,
            asset_digest: capsule.digests.runtime_entry_set.value,
            signature: capsule.signature,
            access: capsule.compatibility?.capsule_1_access ?? capsule.access,
            risk_level: capsule.risk_level,
            profile: capsule.profile,
            context: capsule.context,
            trace: KDNAContextCapsuleTrace(
                payload_encoding: capsule.trace.payload_encoding,
                loaded_by: capsule.trace.loaded_by,
                loaded_at: capsule.trace.loaded_at,
                schema_valid: capsule.trace.schema_valid,
                signature_state: capsule.trace.signature_state,
                profile: capsule.trace.profile
            ),
            extends_chain: extensions?.extends_chain,
            inheritance_applied: extensions?.inheritance_applied,
            resolved_dependencies: extensions?.resolved_dependencies,
            rag_isolation_policy: extensions?.rag_isolation_policy
        )
        try assertCapsule1Success(capsule1, code: "KDNA_CAPSULE_ADAPTER_OUTPUT_INVALID")
        return capsule1
    }

    static func jsonValue(_ capsule: KDNAContextCapsule2) -> KDNAJSONValue {
        var signature: [String: KDNAJSONValue] = ["state": .string(capsule.signature.state)]
        if let issuer = capsule.signature.issuer { signature["issuer"] = .string(issuer) }

        var object: [String: KDNAJSONValue] = [
            "type": .string(capsule.type),
            "version": .string(capsule.version),
            "asset": .object([
                "asset_id": .string(capsule.asset.asset_id),
                "asset_uid": .string(capsule.asset.asset_uid),
                "version": .string(capsule.asset.version),
                "judgment_version": .string(capsule.asset.judgment_version),
            ]),
            "digests": digestEvidenceJSON(capsule.digests),
            "signature": .object(signature),
            "access": .string(capsule.access),
            "risk_level": capsule.risk_level.map(KDNAJSONValue.string) ?? .null,
            "profile": .string(capsule.profile),
            "context": capsule.context,
            "trace": .object([
                "payload_encoding": .string(capsule.trace.payload_encoding),
                "loaded_by": .string(capsule.trace.loaded_by),
                "loaded_at": .string(capsule.trace.loaded_at),
                "input_kind": .string(capsule.trace.input_kind),
                "runtime_eligible": .bool(capsule.trace.runtime_eligible),
                "schema_valid": .bool(capsule.trace.schema_valid),
                "signature_state": .string(capsule.trace.signature_state),
                "profile": .string(capsule.trace.profile),
            ]),
        ]
        if let compatibility = capsule.compatibility {
            object["compatibility"] = compatibilityJSON(compatibility)
        }
        return .object(object)
    }

    private struct DeclaredDigest {
        let value: String
        let source: String
    }

    private static func protocolError(_ code: String, _ message: String) -> KDNACapsule2Error {
        KDNACapsule2Error(code: code, message: message)
    }

    private static func validDigest(_ value: String) -> Bool {
        matches(sha256Pattern, value)
    }

    private static func matches(_ expression: NSRegularExpression, _ value: String) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range) != nil
    }

    private static func normalizeExternal(_ expected: KDNAExpectedDigest?) throws -> DeclaredDigest? {
        guard let expected else { return nil }
        guard validDigest(expected.value), externalSources.contains(expected.source) else {
            throw protocolError(
                "KDNA_DIGEST_EXPECTATION_INVALID",
                "Expected digest must provide a lowercase sha256 value and a factual external source."
            )
        }
        return DeclaredDigest(value: expected.value, source: expected.source)
    }

    private static func normalizeDeclaration(_ value: Any?, source: String) throws -> DeclaredDigest {
        guard let value = value as? String, validDigest(value) else {
            throw protocolError(
                "KDNA_DIGEST_EXPECTATION_INVALID",
                "Declared digest must be a lowercase sha256 value."
            )
        }
        return DeclaredDigest(value: value, source: source)
    }

    private static func contentDeclaration(_ manifest: [String: Any]) throws -> DeclaredDigest? {
        let top = manifest.keys.contains("content_digest")
            ? try normalizeDeclaration(manifest["content_digest"], source: "kdna.json.content_digest")
            : nil
        let authoring = manifest["authoring"] as? [String: Any]
        let nested = authoring?.keys.contains("content_digest") == true
            ? try normalizeDeclaration(
                authoring?["content_digest"],
                source: "kdna.json.authoring.content_digest"
            )
            : nil
        if let top, let nested, top.value != nested.value {
            throw protocolError(
                "KDNA_CONTENT_DIGEST_DECLARATION_CONFLICT",
                "kdna.json content_digest conflicts with authoring.content_digest."
            )
        }
        return top ?? nested
    }

    private static func entrySetDeclaration(_ checksums: [String: Any]?) throws -> DeclaredDigest? {
        guard let checksums else { return nil }
        let canonical = checksums.keys.contains("entry_set_digest")
            ? try normalizeDeclaration(
                checksums["entry_set_digest"],
                source: "checksums.json.entry_set_digest"
            )
            : nil
        let legacy = checksums.keys.contains("asset_digest")
            ? try normalizeDeclaration(
                checksums["asset_digest"],
                source: "checksums.json.asset_digest"
            )
            : nil
        if let canonical, let legacy, canonical.value != legacy.value {
            throw protocolError(
                "KDNA_RUNTIME_ENTRY_SET_DIGEST_DECLARATION_CONFLICT",
                "checksums.json entry_set_digest conflicts with deprecated asset_digest."
            )
        }
        return canonical ?? legacy
    }

    private static func comparison(
        observed: String,
        expected: DeclaredDigest?,
        against: String
    ) throws -> KDNADigestComparison {
        guard let expected else {
            return KDNADigestComparison(
                state: "not_compared",
                against: nil,
                expected: nil,
                source: nil
            )
        }
        return KDNADigestComparison(
            state: observed == expected.value ? "matched" : "mismatched",
            against: against,
            expected: expected.value,
            source: expected.source
        )
    }

    private static func comparisonWithDeclarationPriority(
        observed: String,
        declared: DeclaredDigest?,
        external: DeclaredDigest?,
        declarationTarget: String
    ) throws -> KDNADigestComparison {
        let declaration = try comparison(
            observed: observed,
            expected: declared,
            against: declarationTarget
        )
        if declaration.state == "mismatched" { return declaration }
        if let external {
            return try comparison(observed: observed, expected: external, against: "external_expected")
        }
        return declaration
    }

    private static func jsonObject(_ data: Data, entry: String) throws -> [String: Any] {
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw protocolError(
                    "KDNA_DIGEST_DECLARATION_INVALID",
                    "\(entry) must contain a JSON object."
                )
            }
            return object
        } catch let error as KDNACapsule2Error {
            throw error
        } catch {
            throw protocolError(
                "KDNA_DIGEST_DECLARATION_INVALID",
                "\(entry) contains invalid JSON."
            )
        }
    }

    private static func requiredManifestString(
        _ manifest: [String: Any],
        _ field: String
    ) throws -> String {
        guard let value = manifest[field] as? String, !value.isEmpty else {
            throw protocolError(
                "KDNA_CAPSULE_2_BUILD_INVALID",
                "Runtime manifest \(field) is required."
            )
        }
        return value
    }

    private static func canonicalAccess(_ access: String) -> String {
        accessAliases[access] ?? access
    }

    private static func assertCapsule1Success(
        _ capsule: KDNAContextCapsule,
        code: String
    ) throws {
        guard capsule.type == "kdna.context.capsule", capsule.version == "1.0",
              capsule.trace.schema_valid,
              capsule.signature.state == capsule.trace.signature_state,
              capsule.profile == capsule.trace.profile,
              profiles.contains(capsule.profile),
              signatureStates.contains(capsule.signature.state),
              ["public", "licensed", "remote"].contains(canonicalAccess(capsule.access)),
              case .object = capsule.context else {
            throw protocolError(code, "Capsule 1 does not satisfy successful Runtime invariants.")
        }
    }

    static func validateSuccessfulCapsule(
        _ capsule: KDNAContextCapsule2,
        code: String
    ) throws {
        guard capsule.type == "kdna.context.capsule", capsule.version == "2.0",
              matches(assetIDPattern, capsule.asset.asset_id),
              KDNAJSONFormats.isURI(capsule.asset.asset_uid),
              matches(versionPattern, capsule.asset.version),
              matches(versionPattern, capsule.asset.judgment_version),
              ["public", "licensed", "remote"].contains(capsule.access),
              profiles.contains(capsule.profile),
              signatureStates.contains(capsule.signature.state),
              capsule.trace.payload_encoding == "cbor",
              capsule.trace.loaded_by == "kdna-core",
              KDNAJSONFormats.isDateTime(capsule.trace.loaded_at),
              ["packaged_file", "packaged_bytes"].contains(capsule.trace.input_kind),
              capsule.trace.runtime_eligible,
              capsule.trace.schema_valid,
              capsule.signature.state == capsule.trace.signature_state,
              capsule.profile == capsule.trace.profile,
              capsule.signature.issuer == nil || capsule.signature.issuer?.isEmpty == false,
              case .object = capsule.context else {
            throw protocolError(code, "Capsule 2 does not satisfy successful Runtime invariants.")
        }
        try assertSuccessfulEvidence(capsule.digests)
        if let alias = capsule.compatibility?.capsule_1_access,
           accessAliases[alias] != capsule.access {
            throw protocolError(
                code,
                "Capsule 1 compatibility access does not map to Capsule 2 access."
            )
        }
        if let compatibility = capsule.compatibility, compatibility.isEmpty {
            throw protocolError(code, "Empty Capsule 2 compatibility metadata is not allowed.")
        }
        if let domain = capsule.compatibility?.capsule_1_domain, domain.isEmpty {
            throw protocolError(code, "Capsule 1 compatibility domain must not be empty.")
        }
        if let extensions = capsule.compatibility?.capsule_1_extensions, extensions.isEmpty {
            throw protocolError(code, "Empty Capsule 1 extensions are not allowed.")
        }
        if let extensions = capsule.compatibility?.capsule_1_extensions {
            if let value = extensions.extends_chain, value.arrayValue == nil {
                throw protocolError(code, "Capsule 1 extends_chain compatibility value must be an array.")
            }
            if let value = extensions.resolved_dependencies, value.arrayValue == nil {
                throw protocolError(code, "Capsule 1 resolved_dependencies compatibility value must be an array.")
            }
            if let value = extensions.rag_isolation_policy, value.objectValue == nil {
                throw protocolError(code, "Capsule 1 rag_isolation_policy compatibility value must be an object.")
            }
        }
    }

    private static func assertSuccessfulEvidence(_ evidence: KDNADigestEvidence) throws {
        guard evidence.profile == digestProfile else {
            throw protocolError(
                "KDNA_CAPSULE_2_DIGEST_EVIDENCE_INVALID",
                "Capsule 2 digest evidence is missing."
            )
        }
        let observations = [
            ("asset", evidence.asset, assetBasis, "KDNA_ASSET_DIGEST_MISMATCH"),
            ("content", evidence.content, contentBasis, "KDNA_CONTENT_DIGEST_MISMATCH"),
            (
                "runtime_entry_set",
                evidence.runtime_entry_set,
                runtimeEntrySetBasis,
                "KDNA_RUNTIME_ENTRY_SET_DIGEST_MISMATCH"
            ),
        ]
        for (name, item, basis, mismatchCode) in observations {
            guard let value = item.value, validDigest(value), item.basis == basis else {
                throw protocolError(
                    "KDNA_CAPSULE_2_DIGEST_EVIDENCE_INVALID",
                    "Capsule 2 \(name) digest evidence is invalid."
                )
            }
            switch item.comparison.state {
            case "mismatched":
                throw protocolError(mismatchCode, "Capsule 2 cannot be emitted with \(name) mismatch.")
            case "matched":
                guard item.comparison.expected == value,
                      let against = item.comparison.against,
                      comparisonTargets.contains(against),
                      let source = item.comparison.source,
                      comparisonSources.contains(source) else {
                    throw protocolError(
                        "KDNA_CAPSULE_2_DIGEST_EVIDENCE_INVALID",
                        "Capsule 2 \(name) matched comparison is inconsistent."
                    )
                }
            case "not_compared":
                guard item.comparison.expected == nil,
                      item.comparison.against == nil,
                      item.comparison.source == nil else {
                    throw protocolError(
                        "KDNA_CAPSULE_2_DIGEST_EVIDENCE_INVALID",
                        "Capsule 2 \(name) not_compared evidence claims an expectation."
                    )
                }
            default:
                throw protocolError(
                    "KDNA_CAPSULE_2_DIGEST_EVIDENCE_INVALID",
                    "Capsule 2 \(name) comparison state is invalid."
                )
            }
        }
    }

    private static func digestEvidenceJSON(_ evidence: KDNADigestEvidence) -> KDNAJSONValue {
        .object([
            "profile": .string(evidence.profile),
            "asset": observationJSON(evidence.asset),
            "content": observationJSON(evidence.content),
            "runtime_entry_set": observationJSON(evidence.runtime_entry_set),
        ])
    }

    private static func observationJSON(_ observation: KDNADigestObservation) -> KDNAJSONValue {
        .object([
            "value": observation.value.map(KDNAJSONValue.string) ?? .null,
            "basis": .string(observation.basis),
            "comparison": .object([
                "state": .string(observation.comparison.state),
                "against": observation.comparison.against.map(KDNAJSONValue.string) ?? .null,
                "expected": observation.comparison.expected.map(KDNAJSONValue.string) ?? .null,
                "source": observation.comparison.source.map(KDNAJSONValue.string) ?? .null,
            ]),
        ])
    }

    private static func compatibilityJSON(
        _ compatibility: KDNAContextCapsule2Compatibility
    ) -> KDNAJSONValue {
        var object: [String: KDNAJSONValue] = [:]
        if let domain = compatibility.capsule_1_domain {
            object["capsule_1_domain"] = .string(domain)
        }
        if let access = compatibility.capsule_1_access {
            object["capsule_1_access"] = .string(access)
        }
        if let extensions = compatibility.capsule_1_extensions {
            var values: [String: KDNAJSONValue] = [:]
            if let value = extensions.extends_chain { values["extends_chain"] = value }
            if let value = extensions.inheritance_applied {
                values["inheritance_applied"] = .bool(value)
            }
            if let value = extensions.resolved_dependencies {
                values["resolved_dependencies"] = value
            }
            if let value = extensions.rag_isolation_policy {
                values["rag_isolation_policy"] = value
            }
            object["capsule_1_extensions"] = .object(values)
        }
        return .object(object)
    }
}

public extension KDNARuntime {
    /// Explicit Capsule 2 path. The existing `load` API remains Capsule 1.
    static func loadV2(
        assetURL: URL,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule2 {
        try KDNACapsuleV2.load(
            assetURL: assetURL,
            credential: credential,
            profile: profile,
            expected: expected,
            loadedAt: loadedAt
        )
    }

    /// In-memory Capsule 2 path for already snapshotted packaged bytes.
    static func loadV2(
        assetData: Data,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNAContextCapsule2 {
        try KDNACapsuleV2.load(
            assetData: assetData,
            credential: credential,
            profile: profile,
            expected: expected,
            loadedAt: loadedAt
        )
    }
}
