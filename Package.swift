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
        // Argon2Swift 1.0.4 depends on phc-winner-argon2 by branch, which
        // SwiftPM rejects when the root depends on Argon2Swift as a stable
        // version. Pin the known revision directly so builds remain
        // reproducible while this crypto dependency is replaced or vendored.
        .package(url: "https://github.com/tmthecoder/Argon2Swift.git", revision: "53543623fefe68461b7eeea03d7f96677c2fd76d")
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
