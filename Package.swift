// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ClaudeDont88",
    platforms: [.macOS("15.0")],
    products: [
        .executable(name: "ClaudeDont88", targets: ["GuardApp"]),
        .executable(name: "guard-probe", targets: ["GuardProbe"]),
        .executable(name: "GuardFilter", targets: ["GuardFilter"])
    ],
    targets: [
        .target(name: "GuardCore"),
        .target(name: "GuardMac", dependencies: ["GuardCore"]),
        .executableTarget(name: "GuardApp", dependencies: ["GuardMac", "GuardCore"]),
        .executableTarget(name: "GuardProbe", dependencies: ["GuardMac", "GuardCore"]),
        .executableTarget(name: "GuardFilter", dependencies: ["GuardMac", "GuardCore"]),
        .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore"]),
        .testTarget(name: "GuardMacTests", dependencies: ["GuardMac"])
    ]
)
