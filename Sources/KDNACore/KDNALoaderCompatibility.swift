import Foundation

public struct KDNALoaderCompatibilityAssessment: Equatable, Sendable {
    public let loaderVersion: String
    public let minimumLoaderVersion: String?
    public let loaderCompatible: Bool?

    public init(
        loaderVersion: String,
        minimumLoaderVersion: String?,
        loaderCompatible: Bool?
    ) {
        self.loaderVersion = loaderVersion
        self.minimumLoaderVersion = minimumLoaderVersion
        self.loaderCompatible = loaderCompatible
    }
}

public enum KDNALoaderVersionError: Error, Equatable, LocalizedError {
    case invalidVersion(String)

    public var errorDescription: String? {
        switch self {
        case .invalidVersion(let value):
            return "loader version must use strict x.y.z without leading zeros: \(value)"
        }
    }
}

/// Loader-package compatibility for the current KDNA Runtime.
///
/// This intentionally implements only the strict `x.y.z` coordinate used by
/// `compatibility.min_loader_version`. It does not accept SemVer prerelease or
/// build syntax, and it compares decimal components as strings so untrusted
/// manifest values cannot overflow a fixed-width integer.
public enum KDNALoaderCompatibility {
    public static let currentVersion = "0.19.0"

    public static func parse(_ value: String) -> [String]? {
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 3 else { return nil }
        var parsed: [String] = []
        parsed.reserveCapacity(3)
        for component in components {
            guard !component.isEmpty,
                  component.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  component.count == 1 || component.first != "0" else {
                return nil
            }
            parsed.append(String(component))
        }
        return parsed
    }

    /// Returns `-1`, `0`, or `1` when `left` is lower than, equal to, or
    /// higher than `right`.
    public static func compare(_ left: String, _ right: String) throws -> Int {
        guard let leftComponents = parse(left) else {
            throw KDNALoaderVersionError.invalidVersion(left)
        }
        guard let rightComponents = parse(right) else {
            throw KDNALoaderVersionError.invalidVersion(right)
        }
        for index in 0..<3 {
            let comparison = compareDecimal(
                leftComponents[index],
                rightComponents[index]
            )
            if comparison != 0 { return comparison }
        }
        return 0
    }

    public static func assess(manifest: [String: Any]) -> KDNALoaderCompatibilityAssessment {
        let minimum = (manifest["compatibility"] as? [String: Any])?["min_loader_version"] as? String
        let compatible: Bool?
        if let minimum, parse(minimum) != nil {
            compatible = (try? compare(minimum, currentVersion)).map { $0 <= 0 }
        } else {
            compatible = nil
        }
        return KDNALoaderCompatibilityAssessment(
            loaderVersion: currentVersion,
            minimumLoaderVersion: minimum,
            loaderCompatible: compatible
        )
    }

    static func unsupportedMessage(requiredVersion: String) -> String {
        "KDNA_LOADER_VERSION_UNSUPPORTED: asset requires loader \(requiredVersion), current loader is \(currentVersion)"
    }

    private static func compareDecimal(_ left: String, _ right: String) -> Int {
        if left.count != right.count { return left.count < right.count ? -1 : 1 }
        if left == right { return 0 }
        return left.lexicographicallyPrecedes(right) ? -1 : 1
    }
}
