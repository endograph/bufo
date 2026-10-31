// swift-tools-version: 6.0

import PackageDescription

// Bufo (ARCHITECTURE.md, PLAN.md). BufoContract is what a host and the phone
// link: requests, incidents, and status, with no placement in any type.
// BufoKit is the watcher, linked by no host. bufo is one executable: the
// JSON CLI, and the daemon when launchd starts it as root. No dependencies.
let package = Package(
    name: "bufo",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "BufoContract", targets: ["BufoContract"]),
    ],
    targets: [
        .target(name: "BufoContract"),
        .target(name: "BufoKit", dependencies: ["BufoContract"]),
        .executableTarget(name: "bufo", dependencies: ["BufoKit", "BufoContract"]),
        .testTarget(name: "BufoKitTests", dependencies: ["BufoKit", "BufoContract"]),
        // A host for drills, linking only the contract as a real host does.
        .executableTarget(name: "bufo-testhost", dependencies: ["BufoContract"], path: "Tests/TestHost"),
    ]
)
