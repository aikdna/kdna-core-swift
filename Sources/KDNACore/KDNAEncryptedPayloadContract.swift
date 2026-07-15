import Foundation

/// One fail-closed interpretation of the manifest declaration and the actual
/// `payload.kdnab` CBOR value. Verify, LoadPlan, and authorized loading all use
/// this assessment so credentials cannot turn malformed encryption metadata
/// into an accepted Runtime payload.
struct KDNAEncryptedPayloadAssessment {
    let payload: [String: Any]
    let isEncryptedEnvelope: Bool
    let problems: [String]
}

enum KDNAEncryptedPayloadContract {
    static func inspect(
        manifest: [String: Any],
        payloadData: Data
    ) throws -> KDNAEncryptedPayloadAssessment {
        inspect(
            manifest: manifest,
            payload: try KDNACBOR.decodeObject(payloadData)
        )
    }

    static func inspect(
        manifest: [String: Any],
        payload: [String: Any]
    ) -> KDNAEncryptedPayloadAssessment {
        var problems: [String] = []
        let payloadDescriptor = manifest["payload"] as? [String: Any]
        let payloadDeclaresEncryption = payloadDescriptor?["encrypted"] as? Bool == true
        let hasEncryptionField = manifest.keys.contains("encryption")
        let encryption = manifest["encryption"] as? [String: Any]
        let envelopeProfile = nonEmptyString(payload["profile"])
        let envelopeCiphertext = nonEmptyString(payload["ciphertext"])
        let isEncryptedEnvelope = envelopeProfile != nil && envelopeCiphertext != nil
        let manifestDeclaresEncryption = payloadDeclaresEncryption || hasEncryptionField

        if manifestDeclaresEncryption && !isEncryptedEnvelope {
            problems.append(
                "payload: manifest declares encryption but payload.kdnab is not an encrypted envelope"
            )
        }
        if isEncryptedEnvelope && !manifestDeclaresEncryption {
            problems.append(
                "payload: encrypted envelope is missing its manifest encryption declaration"
            )
        }

        guard manifestDeclaresEncryption || isEncryptedEnvelope else {
            return KDNAEncryptedPayloadAssessment(
                payload: payload,
                isEncryptedEnvelope: false,
                problems: problems
            )
        }

        if payloadDescriptor?["encrypted"] as? Bool != true {
            problems.append("payload: encrypted envelope requires payload.encrypted to be true")
        }
        guard let encryption else {
            problems.append("payload: encrypted payload requires a manifest encryption declaration")
            return KDNAEncryptedPayloadAssessment(
                payload: payload,
                isEncryptedEnvelope: isEncryptedEnvelope,
                problems: problems
            )
        }

        let encryptedEntries = encryption["encrypted_entries"] as? [String]
        if encryptedEntries != ["payload.kdnab"] {
            problems.append(
                "payload: manifest encrypted_entries must declare only payload.kdnab"
            )
        }

        let manifestProfile = nonEmptyString(encryption["profile"])
        switch manifestProfile {
        case KDNA_LICENSED_ENTRY_PROFILE, PASSWORD_PROTECTED_PROFILE,
             KDNA_EXTERNAL_ENVELOPE_PROFILE:
            break
        case "kdna.encryption.password.scrypt":
            problems.append(
                "payload: unsupported encryption profile kdna.encryption.password.scrypt in Swift Runtime"
            )
        case .some(let profile):
            problems.append("payload: unsupported encryption profile \(profile)")
        case nil:
            problems.append("payload: manifest encryption profile is missing")
        }

        if let envelopeProfile, let manifestProfile, envelopeProfile != manifestProfile {
            problems.append(
                "payload: encrypted envelope profile \(envelopeProfile) does not match manifest encryption profile \(manifestProfile)"
            )
        }

        let manifestCoordinate = nonEmptyString(encryption["profile_version"])
        let envelopeCoordinateKey = envelopeProfile == KDNA_EXTERNAL_ENVELOPE_PROFILE
            ? "contract_version"
            : "profile_version"
        let envelopeCoordinate = nonEmptyString(payload[envelopeCoordinateKey])
        if manifestCoordinate == nil {
            problems.append("payload: manifest encryption profile_version is missing")
        } else if manifestCoordinate != KDNA_ENCRYPTION_PROFILE_VERSION {
            problems.append(
                "payload: manifest encryption profile_version must be \(KDNA_ENCRYPTION_PROFILE_VERSION)"
            )
        }
        if envelopeCoordinate == nil {
            problems.append(
                "payload: encrypted envelope \(envelopeCoordinateKey) is missing"
            )
        } else if envelopeCoordinate != KDNA_ENCRYPTION_PROFILE_VERSION {
            problems.append(
                "payload: encrypted envelope \(envelopeCoordinateKey) must be \(KDNA_ENCRYPTION_PROFILE_VERSION)"
            )
        }
        if let manifestCoordinate, let envelopeCoordinate,
           manifestCoordinate != envelopeCoordinate {
            problems.append(
                "payload: encrypted envelope compatibility coordinate \(envelopeCoordinate) does not match manifest encryption profile_version \(manifestCoordinate)"
            )
        }

        return KDNAEncryptedPayloadAssessment(
            payload: payload,
            isEncryptedEnvelope: isEncryptedEnvelope,
            problems: problems
        )
    }

    private static func nonEmptyString(_ value: Any?) -> String? {
        guard let value = value as? String, !value.isEmpty else { return nil }
        return value
    }
}
