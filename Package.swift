// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "kdna-core-swift",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "KDNACore", targets: ["KDNACore"])],
    dependencies: [],
    targets: [
        .target(name: "KDNACore", resources: [.copy("Resources/Schemas")], linkerSettings: [.linkedLibrary("z")]),
        .testTarget(name: "KDNACoreTests", dependencies: ["KDNACore"], path: "Tests/PublicCoreTests", resources: [.copy("Fixtures")])
    ]
)
