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
        .package(url: "https://github.com/rkreutz/Argon2Kit.git", from: "0.1.1")
    ],
    targets: [
        .target(
            name: "KDNACore",
            dependencies: ["Argon2Kit"],
            resources: [
                .copy("Resources/Schemas")
            ]
        ),
        .testTarget(
            name: "KDNACoreTests",
            dependencies: ["KDNACore"],
            resources: [
                .process("Fixtures")
            ]
        ),
    ]
)
