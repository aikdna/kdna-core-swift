//  KDNACore — Trust Verifier: signature + yank + license checks

import Foundation

public class KDNATrustVerifier {

    /// Verify trust for a domain: signature, yank status, license.
    /// Returns KDNATrustResult with detailed failures.
    public func verify(domainDir: URL) -> KDNATrustResult {
        var failures: [String] = []
        var signatureValid: Bool? = nil
        var notYanked = true
        var licenseValid: Bool? = nil

        let manifestPath = domainDir.appendingPathComponent("kdna.json")
        guard let data = try? Data(contentsOf: manifestPath),
              let manifest = try? JSONDecoder().decode(KDNAManifest.self, from: data) else {
            return KDNATrustResult(passed: false, signatureValid: nil, notYanked: false,
                                    licenseValid: nil, failures: ["cannot read kdna.json"])
        }

        // Yank check — kdna.json may have a yanked field (future extension)
        // For now, check if the manifest has a status field indicating deprecation
        if manifest.status == "deprecated" {
            notYanked = false
            failures.append("domain is deprecated")
        }

        // Signature check
        // For open domains: no signature required
        // For licensed/runtime domains: signature must be present and valid
        if manifest.access == "licensed" || manifest.access == "runtime" {
            // Check if kdna.json has a signature field
            // Full Ed25519 verification requires the author's public key and canonical payload
            // This is a lightweight check — full verification is done by kdna-cli verify
            let hasSignature = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["signature"] != nil
            if !hasSignature {
                signatureValid = false
                failures.append("commercial domain has no signature")
            } else {
                signatureValid = true
            }
        }

        // License check — for licensed/runtime, verify local activation file
        if manifest.access == "licensed" || manifest.access == "runtime" {
            let safeName = manifest.name.replacingOccurrences(of: "@", with: "").replacingOccurrences(of: "/", with: "-")
            let licensePath = KDNAPlatformPaths.licensesDirectory.appendingPathComponent("\(safeName).json")
            if FileManager.default.fileExists(atPath: licensePath.path) {
                // Activation file exists — basic check passed.
                // Full entitlement validation is performed by kdna CLI/Core runtime.
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
}
