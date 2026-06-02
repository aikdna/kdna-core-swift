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
        .package(url: "https://github.com/tmthecoder/Argon2Swift.git", .branch("main"))
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
