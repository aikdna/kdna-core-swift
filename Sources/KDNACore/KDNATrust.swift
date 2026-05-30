//  KDNACore — Trust Verifier: Ed25519 signature + yank + license checks
//
//  Aligned with @aikdna/kdna-core/src/asset-reader.js verifySignature()

import Foundation
import CryptoKit

public class KDNATrustVerifier {

    /// Verify trust for a domain: Ed25519 signature, yank status, license.
    public func verify(domainDir: URL) -> KDNATrustResult {
        var failures: [String] = []
        var signatureValid: Bool? = nil
        var notYanked = true
        var licenseValid: Bool? = nil

        let manifestURL = domainDir.appendingPathComponent("kdna.json")
        guard let data = try? Data(contentsOf: manifestURL),
              let manifestObj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let manifest = try? JSONDecoder().decode(KDNAManifest.self, from: data) else {
            return KDNATrustResult(passed: false, signatureValid: nil, notYanked: false,
                                    licenseValid: nil, failures: ["cannot read kdna.json"])
        }

        // Yank check
        if manifest.status == "deprecated" {
            notYanked = false; failures.append("domain is deprecated")
        }

        // ── Ed25519 signature verification ─────────────────
        let requiresSig = manifest.access == "licensed" || manifest.access == "runtime"
        if requiresSig || manifestObj["signature"] != nil {
            signatureValid = verifyEd25519Signature(domainDir: domainDir, manifestObj: manifestObj)
            if signatureValid == false {
                failures.append("Ed25519 signature verification failed")
            } else if signatureValid == nil {
                failures.append("signature present but missing public key for verification")
            }
        }

        // ── License check ──────────────────────────────────
        if manifest.access == "licensed" || manifest.access == "runtime" {
            let safeName = manifest.name.replacingOccurrences(of: "@", with: "").replacingOccurrences(of: "/", with: "-")
            let licensePath = KDNAPlatformPaths.licensesDirectory.appendingPathComponent("\(safeName).json")
            if FileManager.default.fileExists(atPath: licensePath.path) {
                licenseValid = true
            } else {
                licenseValid = false
                failures.append("no local activation found for commercial domain")
            }
        }

        return KDNATrustResult(
            passed: failures.isEmpty,
            signatureValid: signatureValid,
            notYanked: notYanked,
            licenseValid: licenseValid,
            failures: failures
        )
    }

    // MARK: - Ed25519 Verification

    /// Full Ed25519 signature verification for a .kdna domain directory.
    /// Returns true if signature is valid, false if invalid, nil if can't verify.
    private func verifyEd25519Signature(domainDir: URL, manifestObj: [String: Any]) -> Bool? {
        guard let signatureField = manifestObj["signature"] as? String,
              signatureField.hasPrefix("ed25519:") else { return nil }

        let signatureHex = String(signatureField.dropFirst(7)) // strip "ed25519:"

        // Get public key from manifest author block
        let author = manifestObj["author"] as? [String: Any]
        guard let pubkey = author?["public_key_pem"] as? String ?? author?["pubkey"] as? String else {
            return nil
        }
        let isPEM = pubkey.hasPrefix("-----BEGIN")

        // Build canonical signing payload from JSON entries in the domain directory
        guard let payload = buildCanonicalSigningPayload(domainDir: domainDir, manifestObj: manifestObj) else {
            return nil
        }

        do {
            if isPEM {
                try KDNACrypto.verifyEd25519PEM(payload, signatureHex: signatureHex, publicKeyPEM: pubkey)
            } else {
                // pubkey format: "ed25519:<hex>" — extract raw hex
                let rawKey = pubkey.hasPrefix("ed25519:") ? String(pubkey.dropFirst(8)) : pubkey
                try KDNACrypto.verifyEd25519(payload, signatureHex: signatureHex, publicKeyHex: rawKey)
            }
            return true
        } catch {
            return false
        }
    }

    /// Build the canonical signing payload from .kdna domain directory entries.
    /// Mirrors KDNAContentDigest.canonicalSigningPayload for directory-based access.
    private func buildCanonicalSigningPayload(domainDir: URL, manifestObj: [String: Any]) -> Data? {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: domainDir, includingPropertiesForKeys: nil) else {
            return nil
        }

        var entries: [String: Data] = [:]
        for fileURL in files {
            let name = fileURL.lastPathComponent
            guard name.lowercased().hasSuffix(".json"), name != "signature.json" else { continue }
            guard let data = try? Data(contentsOf: fileURL) else { continue }
            entries[name] = data
        }

        let payload = KDNAContentDigest.canonicalSigningPayload(entries: entries)
        return Data(payload.utf8)
    }
}
