import Foundation

// The public asset-hung faces (c0+f2 early-alignment binding, design note §4/§6):
// KDNA* prefix, faces hang on the asset, and the phase tokens (admitted
// request / authority / snapshot) are the only channel through the phases —
// every face takes them as mandatory parameters. This is a thin wrapper over
// the internal SectionFaces machinery: same phase order, same closed
// envelopes; the public boundary maps internal errors to the closed
// KDNASectionError code and the authority callback to the confirmed `Bool?`
// rule — only `.some(true)` grants, `.none` / `.some(false)` / thrown errors
// all deny (the Node strict `!== true`).
public struct KDNASectionError: Error, Equatable {
    public let code: String
    public init(code: String) { self.code = code }
}

public final class KDNASectionAsset {
    public let bytes: [UInt8]
    public let fileSHA256: String
    public let manifest: KDNAValue
    public let tuple: KDNAValue
    private init(bytes: [UInt8], fileSHA256: String, manifest: KDNAValue, tuple: KDNAValue) {
        self.bytes = bytes; self.fileSHA256 = fileSHA256; self.manifest = manifest; self.tuple = tuple
    }
    /// Admission of the bytes: the container rules, the manifest view and the
    /// sections contract must hold before a face can be used; an optional
    /// expected digest is checked first.
    public static func open(bytes: [UInt8], expectedSHA256: String? = nil) throws -> KDNASectionAsset {
        do {
            let digest = sha(Data(bytes))
            if let expected = expectedSHA256, !exact(expected, digest) { throw PublicFailure("READ_INPUT_INVALID") }
            let entries = try SectionContainer.parse(Data(bytes))
            guard let manifestEntry = entries.first(where: { $0.name == "kdna.json" }) else { throw PublicFailure("READ_CORE_INVALID") }
            let manifest = try SectionManifest.load(manifestEntry.bytes)
            let tuple = try SectionContract.loadedContract.get()["module"]["versionTuple"]
            return KDNASectionAsset(bytes: bytes, fileSHA256: digest, manifest: manifest, tuple: tuple)
        } catch let failure as PublicFailure {
            throw KDNASectionError(code: failure.code)
        } catch {
            throw KDNASectionError(code: "READ_CORE_CAPABILITY_UNAVAILABLE")
        }
    }
    public func admitSectionRequest(_ candidate: KDNAValue) throws -> KDNAAdmittedSectionRequest {
        do { return try SectionFaces.admitSectionRequest(candidate) }
        catch let failure as PublicFailure { throw KDNASectionError(code: failure.code) }
        catch { throw KDNASectionError(code: "READ_CORE_INVALID") }
    }
    /// The canonical whole_asset request for this asset's contract tuple.
    public func admitWholeReadRequest(requestId: String, budgetBytes: Int) throws -> KDNAAdmittedSectionRequest {
        try admitSectionRequest(["request_id": .string(requestId), "tuple": tuple, "budget_bytes": .number(Double(budgetBytes)),
                                 "mode": "whole_asset", "selection": .null, "handle": .null])
    }
    public func createReadAuthority(_ authorize: @escaping (KDNAValue) async throws -> Bool?,
                                    signaturePolicy: KDNAValue? = nil) throws -> KDNASectionReadAuthority {
        do {
            return try SectionFaces.createSectionReadAuthority({ value in
                (try await authorize(value)) == true ? .bool(true) : nil
            }, signaturePolicy: signaturePolicy ?? SectionSignatures.defaultPolicy)
        } catch let failure as PublicFailure { throw KDNASectionError(code: failure.code) }
        catch { throw KDNASectionError(code: "READ_CORE_INVALID") }
    }
    /// Whole-asset read. The outcome carries the closed envelope; accepted
    /// reads also carry the opaque snapshot token (uninspectable data stays
    /// behind `inspect()`).
    public func readWhole(_ admitted: KDNAAdmittedSectionRequest, _ authority: KDNASectionReadAuthority) async -> SectionFaces.ReadOutcome {
        await SectionFaces.readWhole(bytes, admitted, authority)
    }
}
