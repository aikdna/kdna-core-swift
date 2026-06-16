// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "kdna-core-swift",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "KDNACore",
            targets: ["KDNACore"]
        ),
    ],
    dependencies: [
        // PR-8: pin to a specific tag (was .branch("main"), which floats
        // and is a known anti-pattern for crypto deps). The tag was the
        // latest at the time of audit (2026-06-16) and matches the SHA
        // recorded in Package.resolved.
        .package(url: "https://github.com/tmthecoder/Argon2Swift.git", exact: "1.0.4")
    ],
    targets: [
        .target(
            name: "KDNACore",
            dependencies: ["Argon2Swift"]
        ),
        .testTarget(
            name: "KDNACoreTests",
            dependencies: ["KDNACore"]
        ),
    ]
)
