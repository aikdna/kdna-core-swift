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
    targets: [
        .target(
            name: "KDNACore",
            dependencies: []
        ),
        .testTarget(
            name: "KDNACoreTests",
            dependencies: ["KDNACore"]
        ),
    ]
)
