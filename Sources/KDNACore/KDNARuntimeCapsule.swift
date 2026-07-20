import Foundation
import CryptoKit

/// Stable protocol error for the current Runtime Capsule and execution contracts.
public struct KDNARuntimeContractError: Error, LocalizedError, Equatable, Sendable {
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

    private enum CodingKeys: String, CodingKey { case state, against, expected, source }

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

    private enum CodingKeys: String, CodingKey { case value, basis, comparison }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if let value { try container.encode(value, forKey: .value) }
        else { try container.encodeNil(forKey: .value) }
        try container.encode(basis, forKey: .basis)
        try container.encode(comparison, forKey: .comparison)
    }
}

public struct KDNADigestEvidence: Codable, Equatable, Sendable {
    public let profile: String
    public let profile_version: String
    public let asset: KDNADigestObservation
    public let content: KDNADigestObservation
    public let runtime_entry_set: KDNADigestObservation

    public init(
        profile: String = "kdna.digest-evidence",
        profile_version: String = "0.1.0",
        asset: KDNADigestObservation,
        content: KDNADigestObservation,
        runtime_entry_set: KDNADigestObservation
    ) {
        self.profile = profile
        self.profile_version = profile_version
        self.asset = asset
        self.content = content
        self.runtime_entry_set = runtime_entry_set
    }
}

public struct KDNARuntimeCapsuleAsset: Codable, Equatable, Sendable {
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
}

public struct KDNARuntimeCapsuleSignature: Codable, Equatable, Sendable {
    public let state: String

    public init(state: String = "absent") {
        self.state = state
    }
}

public struct KDNARuntimeCapsuleTrace: Codable, Equatable, Sendable {
    public let payload_encoding: String
    public let loaded_by: String
    public let loaded_at: String
    public let input_kind: String
    public let runtime_eligible: Bool
    public let schema_valid: Bool
    public let signature_state: String
    public let profile: String

    public init(
        payload_encoding: String = "cbor",
        loaded_by: String = "kdna-core",
        loaded_at: String,
        input_kind: String,
        runtime_eligible: Bool = true,
        schema_valid: Bool = true,
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
}

/// The sole public Runtime projection contract.
public struct KDNARuntimeCapsule: Codable, Equatable, Sendable {
    public let type: String
    public let contract_version: String
    public let asset: KDNARuntimeCapsuleAsset
    public let digests: KDNADigestEvidence
    public let signature: KDNARuntimeCapsuleSignature
    public let access: String
    public let profile: String
    public let context: KDNAJSONValue
    public let trace: KDNARuntimeCapsuleTrace

    public init(
        type: String = "kdna.runtime-capsule",
        contract_version: String = "0.1.0",
        asset: KDNARuntimeCapsuleAsset,
        digests: KDNADigestEvidence,
        signature: KDNARuntimeCapsuleSignature,
        access: String,
        profile: String,
        context: KDNAJSONValue,
        trace: KDNARuntimeCapsuleTrace
    ) {
        self.type = type
        self.contract_version = contract_version
        self.asset = asset
        self.digests = digests
        self.signature = signature
        self.access = access
        self.profile = profile
        self.context = context
        self.trace = trace
    }

    private enum CodingKeys: String, CodingKey {
        case type, contract_version, asset, digests, signature, access, profile, context, trace
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(contract_version, forKey: .contract_version)
        try container.encode(asset, forKey: .asset)
        try container.encode(digests, forKey: .digests)
        try container.encode(signature, forKey: .signature)
        try container.encode(access, forKey: .access)
        try container.encode(profile, forKey: .profile)
        try container.encode(context, forKey: .context)
        try container.encode(trace, forKey: .trace)
    }

    public init(from decoder: Decoder) throws {
        let value = try KDNAJSONValue(from: decoder)
        let issues = KDNACanonicalSchemas.validateRuntimeCapsule(value.anyValue)
        guard issues.isEmpty else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Runtime Capsule schema invalid: \(issues.joined(separator: "; "))"
            ))
        }
        guard let object = value.objectValue,
              let assetObject = object["asset"]?.objectValue,
              let digestsObject = object["digests"]?.objectValue,
              let signatureObject = object["signature"]?.objectValue,
              let traceObject = object["trace"]?.objectValue,
              let type = object["type"]?.stringValue,
              let contractVersion = object["contract_version"]?.stringValue,
              let access = object["access"]?.stringValue,
              let profile = object["profile"]?.stringValue,
              let context = object["context"],
              let parsedAsset = Self.parseAsset(assetObject),
              let parsedDigests = Self.parseDigests(digestsObject),
              let parsedSignature = Self.parseSignature(signatureObject),
              let parsedTrace = Self.parseTrace(traceObject) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Runtime Capsule could not be materialized."
            ))
        }
        self.type = type
        self.contract_version = contractVersion
        self.asset = parsedAsset
        self.digests = parsedDigests
        self.signature = parsedSignature
        self.access = access
        self.profile = profile
        self.context = context
        self.trace = parsedTrace
        guard Self.isSuccessful(self) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Runtime Capsule semantic invariants failed."
            ))
        }
    }

    public var jsonValue: KDNAJSONValue {
        return .object([
            "type": .string(type),
            "contract_version": .string(contract_version),
            "asset": .object([
                "asset_id": .string(asset.asset_id),
                "asset_uid": .string(asset.asset_uid),
                "version": .string(asset.version),
                "judgment_version": .string(asset.judgment_version),
            ]),
            "digests": digests.jsonValue,
            "signature": .object(["state": .string(signature.state)]),
            "access": .string(access),
            "profile": .string(profile),
            "context": context,
            "trace": .object([
                "payload_encoding": .string(trace.payload_encoding),
                "loaded_by": .string(trace.loaded_by),
                "loaded_at": .string(trace.loaded_at),
                "input_kind": .string(trace.input_kind),
                "runtime_eligible": .bool(trace.runtime_eligible),
                "schema_valid": .bool(trace.schema_valid),
                "signature_state": .string(trace.signature_state),
                "profile": .string(trace.profile),
            ]),
        ])
    }

    private static func parseAsset(_ object: [String: KDNAJSONValue]) -> KDNARuntimeCapsuleAsset? {
        guard let assetID = object["asset_id"]?.stringValue,
              let assetUID = object["asset_uid"]?.stringValue,
              let version = object["version"]?.stringValue,
              let judgmentVersion = object["judgment_version"]?.stringValue else { return nil }
        return KDNARuntimeCapsuleAsset(
            asset_id: assetID,
            asset_uid: assetUID,
            version: version,
            judgment_version: judgmentVersion
        )
    }

    private static func parseDigests(_ object: [String: KDNAJSONValue]) -> KDNADigestEvidence? {
        guard let profile = object["profile"]?.stringValue,
              let version = object["profile_version"]?.stringValue,
              let asset = parseObservation(object["asset"]),
              let content = parseObservation(object["content"]),
              let entrySet = parseObservation(object["runtime_entry_set"]) else { return nil }
        return KDNADigestEvidence(
            profile: profile,
            profile_version: version,
            asset: asset,
            content: content,
            runtime_entry_set: entrySet
        )
    }

    private static func parseObservation(_ value: KDNAJSONValue?) -> KDNADigestObservation? {
        guard let object = value?.objectValue,
              let basis = object["basis"]?.stringValue,
              let comparisonObject = object["comparison"]?.objectValue,
              let state = comparisonObject["state"]?.stringValue else { return nil }
        return KDNADigestObservation(
            value: object["value"]?.stringValue,
            basis: basis,
            comparison: KDNADigestComparison(
                state: state,
                against: comparisonObject["against"]?.stringValue,
                expected: comparisonObject["expected"]?.stringValue,
                source: comparisonObject["source"]?.stringValue
            )
        )
    }

    private static func parseSignature(_ object: [String: KDNAJSONValue]) -> KDNARuntimeCapsuleSignature? {
        guard let state = object["state"]?.stringValue else { return nil }
        return KDNARuntimeCapsuleSignature(state: state)
    }

    private static func parseTrace(_ object: [String: KDNAJSONValue]) -> KDNARuntimeCapsuleTrace? {
        guard let payloadEncoding = object["payload_encoding"]?.stringValue,
              let loadedBy = object["loaded_by"]?.stringValue,
              let loadedAt = object["loaded_at"]?.stringValue,
              let inputKind = object["input_kind"]?.stringValue,
              let runtimeEligible = object["runtime_eligible"]?.boolValue,
              let schemaValid = object["schema_valid"]?.boolValue,
              let signatureState = object["signature_state"]?.stringValue,
              let profile = object["profile"]?.stringValue else { return nil }
        return KDNARuntimeCapsuleTrace(
            payload_encoding: payloadEncoding,
            loaded_by: loadedBy,
            loaded_at: loadedAt,
            input_kind: inputKind,
            runtime_eligible: runtimeEligible,
            schema_valid: schemaValid,
            signature_state: signatureState,
            profile: profile
        )
    }

    static func isSuccessful(_ capsule: KDNARuntimeCapsule) -> Bool {
        capsule.type == "kdna.runtime-capsule" &&
            capsule.contract_version == "0.1.0" &&
            capsule.trace.runtime_eligible && capsule.trace.schema_valid &&
            capsule.trace.signature_state == capsule.signature.state &&
            capsule.trace.profile == capsule.profile &&
            capsule.context.objectValue != nil &&
            [capsule.digests.asset, capsule.digests.content, capsule.digests.runtime_entry_set]
                .allSatisfy { $0.value != nil && ["matched", "not_compared"].contains($0.comparison.state) }
    }
}

/// RFC 8785 JSON Canonicalization used by P and every execution-contract digest.
public enum KDNAJCS {
    public static func canonicalString(_ value: KDNAJSONValue) throws -> String { try serialize(value) }
    public static func canonicalData(_ value: KDNAJSONValue) throws -> Data { Data(try serialize(value).utf8) }

    private static func serialize(_ value: KDNAJSONValue) throws -> String {
        switch value {
        case .null: return "null"
        case .bool(let value): return value ? "true" : "false"
        case .string(let value): return quote(value)
        case .number(let value): return try number(value)
        case .array(let values): return "[" + (try values.map(serialize)).joined(separator: ",") + "]"
        case .object(let object):
            return "{" + (try object.keys.sorted(by: utf16Less).map {
                "\(quote($0)):\(try serialize(object[$0]!))"
            }).joined(separator: ",") + "}"
        }
    }

    private static func quote(_ value: String) -> String {
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
        return result + "\""
    }

    private static func number(_ value: Double) throws -> String {
        guard value.isFinite else {
            throw KDNARuntimeContractError(
                code: "KDNA_JCS_NON_FINITE_NUMBER",
                message: "JCS input contains a non-finite number."
            )
        }
        if value == 0 { return "0" }
        let raw = String(value).lowercased()
        guard let marker = raw.firstIndex(of: "e") else {
            return raw.hasSuffix(".0") ? String(raw.dropLast(2)) : raw
        }
        let mantissa = String(raw[..<marker])
        guard let exponent = Int(raw[raw.index(after: marker)...]) else {
            throw KDNARuntimeContractError(
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

public enum KDNARuntimeCapsuleCore {
    public static let contractVersion = "0.1.0"
    public static let digestProfile = "kdna.digest-evidence"
    public static let digestProfileVersion = "0.1.0"
    public static let deliveryDigestProfile = "kdna.canonicalization.runtime-capsule-jcs"
    public static let deliveryDigestProfileVersion = "0.1.0"
    public static let assetBasis = "kdna.digest-basis.container-bytes"
    public static let contentBasis = "kdna.digest-basis.content-tree"
    public static let runtimeEntrySetBasis = "kdna.digest-basis.runtime-entry-set"

    private static let externalSources: Set<String> = ["caller", "registry", "install_receipt", "lockfile"]

    public static func computeAssetDigest(_ bytes: Data) -> String {
        "sha256:" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    public static func computeRuntimeEntrySetDigest(manifest: Data, payload: Data) -> String {
        KDNAChecksumDigests.computeRuntimeEntrySetDigest(manifest: manifest, payload: payload)
    }

    public static func computeDeliveryDigest(_ capsule: KDNARuntimeCapsule) throws -> String {
        computeAssetDigest(try KDNAJCS.canonicalData(capsule.jsonValue))
    }

    public static func computeDigestEvidence(
        assetData: Data,
        expected: KDNAExpectedDigests = KDNAExpectedDigests()
    ) throws -> KDNADigestEvidence {
        let reader = KDNAAssetReader()
        let asset: KDNAAsset
        do { asset = try reader.open(data: assetData) }
        catch { throw self.error("KDNA_DIGEST_INPUT_INVALID", "Digest evidence requires packaged KDNA bytes.") }
        guard reader.hasEntry(asset: asset, name: "kdna.json"),
              reader.hasEntry(asset: asset, name: "payload.kdnab") else {
            throw error("KDNA_DIGEST_INPUT_INVALID", "Digest evidence requires current Runtime entries.")
        }
        let manifestData = try reader.readEntry(asset: asset, name: "kdna.json")
        let payloadData = try reader.readEntry(asset: asset, name: "payload.kdnab")
        let manifest = try jsonObject(manifestData, entry: "kdna.json")
        let checksums = reader.hasEntry(asset: asset, name: "checksums.json")
            ? try jsonObject(reader.readEntry(asset: asset, name: "checksums.json"), entry: "checksums.json")
            : nil
        let observedAsset = computeAssetDigest(assetData)
        let observedContent: String
        do { observedContent = try KDNAContentDigest.computeValidated(asset: asset, reader: reader) }
        catch { throw self.error("KDNA_DIGEST_INPUT_INVALID", error.localizedDescription) }
        let observedEntrySet = computeRuntimeEntrySetDigest(manifest: manifestData, payload: payloadData)
        let declaredContent = try contentDeclaration(manifest)
        let declaredEntrySet = try entrySetDeclaration(checksums)
        return KDNADigestEvidence(
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

    public static func load(
        assetData: Data,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNARuntimeCapsule {
        try build(
            assetData: assetData,
            sourcePath: "<packaged-bytes>",
            inputKind: "packaged_bytes",
            credential: credential,
            profile: profile,
            expected: expected,
            loadedAt: loadedAt
        )
    }

    public static func load(
        assetURL: URL,
        credential: KDNACredential = .none,
        profile: String = "compact",
        expected: KDNAExpectedDigests = KDNAExpectedDigests(),
        loadedAt: String? = nil
    ) throws -> KDNARuntimeCapsule {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: assetURL.path, isDirectory: &isDirectory), isDirectory.boolValue {
            throw error("KDNA_ASSET_FILE_REQUIRED", "Runtime loading requires final packaged KDNA bytes.")
        }
        let bytes: Data
        do { bytes = try Data(contentsOf: assetURL) }
        catch { throw self.error("KDNA_RUNTIME_CAPSULE_INPUT_INVALID", "Cannot read packaged KDNA asset.") }
        return try build(
            assetData: bytes,
            sourcePath: assetURL.path,
            inputKind: "packaged_file",
            credential: credential,
            profile: profile,
            expected: expected,
            loadedAt: loadedAt
        )
    }

    private static func build(
        assetData: Data,
        sourcePath: String,
        inputKind: String,
        credential: KDNACredential,
        profile: String,
        expected: KDNAExpectedDigests,
        loadedAt: String?
    ) throws -> KDNARuntimeCapsule {
        let digests = try computeDigestEvidence(assetData: assetData, expected: expected)
        try requireSuccessfulEvidence(digests)
        let loaded = try KDNALoadPlanCore.authorizedPayload(
            assetData: assetData,
            sourcePath: sourcePath,
            credential: credential
        )
        let manifest = loaded.layout.manifest
        let context = try KDNALoadPlanCore.profileContent(
            profile: profile,
            manifest: manifest,
            payload: loaded.payload
        )
        guard let assetID = manifest["asset_id"] as? String,
              let assetUID = manifest["asset_uid"] as? String,
              let version = manifest["version"] as? String,
              let judgmentVersion = manifest["judgment_version"] as? String,
              let access = loaded.plan.access else {
            throw error("KDNA_RUNTIME_CAPSULE_BUILD_INVALID", "Runtime manifest identity is incomplete.")
        }
        let signatureState = "absent"
        let timestamp = loadedAt ?? ISO8601DateFormatter().string(from: Date())
        let capsule = KDNARuntimeCapsule(
            asset: KDNARuntimeCapsuleAsset(
                asset_id: assetID,
                asset_uid: assetUID,
                version: version,
                judgment_version: judgmentVersion
            ),
            digests: digests,
            signature: KDNARuntimeCapsuleSignature(state: signatureState),
            access: access,
            profile: profile,
            context: KDNAJSONValue(any: context),
            trace: KDNARuntimeCapsuleTrace(
                loaded_at: timestamp,
                input_kind: inputKind,
                signature_state: signatureState,
                profile: profile
            )
        )
        let issues = KDNACanonicalSchemas.validateRuntimeCapsule(capsule.jsonValue.anyValue)
        guard issues.isEmpty, KDNARuntimeCapsule.isSuccessful(capsule) else {
            throw error(
                "KDNA_RUNTIME_CAPSULE_BUILD_INVALID",
                "Runtime Capsule does not satisfy the current contract: \(issues.joined(separator: "; "))"
            )
        }
        return capsule
    }

    private struct DeclaredDigest { let value: String; let source: String }

    private static func normalizeExternal(_ value: KDNAExpectedDigest?) throws -> DeclaredDigest? {
        guard let value else { return nil }
        guard validDigest(value.value), externalSources.contains(value.source) else {
            throw error("KDNA_DIGEST_EXPECTATION_INVALID", "Expected digest source or value is invalid.")
        }
        return DeclaredDigest(value: value.value, source: value.source)
    }

    private static func contentDeclaration(_ manifest: [String: Any]) throws -> DeclaredDigest? {
        let top = manifest.keys.contains("content_digest")
            ? try declaration(manifest["content_digest"], source: "kdna.json.content_digest") : nil
        let authoring = manifest["authoring"] as? [String: Any]
        let nested = authoring?.keys.contains("content_digest") == true
            ? try declaration(authoring?["content_digest"], source: "kdna.json.authoring.content_digest") : nil
        if let top, let nested, top.value != nested.value {
            throw error("KDNA_CONTENT_DIGEST_DECLARATION_CONFLICT", "Content digest declarations conflict.")
        }
        return top ?? nested
    }

    private static func entrySetDeclaration(_ checksums: [String: Any]?) throws -> DeclaredDigest? {
        guard let checksums, checksums.keys.contains("entry_set_digest") else { return nil }
        return try declaration(checksums["entry_set_digest"], source: "checksums.json.entry_set_digest")
    }

    private static func declaration(_ value: Any?, source: String) throws -> DeclaredDigest {
        guard let value = value as? String, validDigest(value) else {
            throw error("KDNA_DIGEST_EXPECTATION_INVALID", "Declared digest is not lowercase sha256.")
        }
        return DeclaredDigest(value: value, source: source)
    }

    private static func comparison(
        observed: String,
        expected: DeclaredDigest?,
        against: String
    ) throws -> KDNADigestComparison {
        guard let expected else {
            return KDNADigestComparison(state: "not_compared", against: nil, expected: nil, source: nil)
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
        let result = try comparison(observed: observed, expected: declared, against: declarationTarget)
        if result.state == "mismatched" { return result }
        if let external {
            return try comparison(observed: observed, expected: external, against: "external_expected")
        }
        return result
    }

    private static func requireSuccessfulEvidence(_ evidence: KDNADigestEvidence) throws {
        let observations = [
            (evidence.asset, assetBasis, "KDNA_ASSET_DIGEST_MISMATCH"),
            (evidence.content, contentBasis, "KDNA_CONTENT_DIGEST_MISMATCH"),
            (evidence.runtime_entry_set, runtimeEntrySetBasis, "KDNA_RUNTIME_ENTRY_SET_DIGEST_MISMATCH"),
        ]
        guard evidence.profile == digestProfile, evidence.profile_version == digestProfileVersion else {
            throw error("KDNA_DIGEST_EVIDENCE_INVALID", "Digest evidence profile is invalid.")
        }
        for (observation, basis, mismatchCode) in observations {
            guard observation.value.map(validDigest) == true, observation.basis == basis else {
                throw error("KDNA_DIGEST_EVIDENCE_INVALID", "Digest observation is invalid.")
            }
            if observation.comparison.state == "mismatched" {
                throw error(mismatchCode, "Runtime Capsule cannot be emitted with a digest mismatch.")
            }
            guard ["matched", "not_compared"].contains(observation.comparison.state) else {
                throw error("KDNA_DIGEST_EVIDENCE_INVALID", "Digest comparison is not successful.")
            }
        }
    }

    private static func validDigest(_ value: String) -> Bool {
        value.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    private static func jsonObject(_ data: Data, entry: String) throws -> [String: Any] {
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw error("KDNA_DIGEST_DECLARATION_INVALID", "\(entry) must be a JSON object.")
            }
            return object
        } catch let error as KDNARuntimeContractError { throw error }
        catch { throw self.error("KDNA_DIGEST_DECLARATION_INVALID", "\(entry) contains invalid JSON.") }
    }

    private static func error(_ code: String, _ message: String) -> KDNARuntimeContractError {
        KDNARuntimeContractError(code: code, message: message)
    }
}

extension KDNAJSONValue {
    var anyValue: Any {
        switch self {
        case .object(let object): return object.mapValues(\.anyValue)
        case .array(let array): return array.map(\.anyValue)
        case .string(let value): return value
        case .number(let value): return value
        case .bool(let value): return value
        case .null: return NSNull()
        }
    }

    var boolValue: Bool? {
        guard case .bool(let value) = self else { return nil }
        return value
    }
}

private extension KDNADigestEvidence {
    var jsonValue: KDNAJSONValue {
        .object([
            "profile": .string(profile),
            "profile_version": .string(profile_version),
            "asset": asset.jsonValue,
            "content": content.jsonValue,
            "runtime_entry_set": runtime_entry_set.jsonValue,
        ])
    }
}

private extension KDNADigestObservation {
    var jsonValue: KDNAJSONValue {
        .object([
            "value": value.map(KDNAJSONValue.string) ?? .null,
            "basis": .string(basis),
            "comparison": .object([
                "state": .string(comparison.state),
                "against": comparison.against.map(KDNAJSONValue.string) ?? .null,
                "expected": comparison.expected.map(KDNAJSONValue.string) ?? .null,
                "source": comparison.source.map(KDNAJSONValue.string) ?? .null,
            ]),
        ])
    }
}
