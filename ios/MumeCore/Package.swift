// swift-tools-version: 5.9
import PackageDescription

/// MumeCore — the Swift mirror of the Kotlin `:core` module.
///
/// Same rule IDs, same scoring arithmetic, same hash specification, same
/// on-disk bundle format. The golden fixtures in `shared/fixtures` are run
/// against both implementations and must produce identical integers.
///
/// Like its Kotlin counterpart this target has **no dependencies at all**, so
/// nothing on its classpath is even capable of opening a socket.
let package = Package(
    name: "MumeCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "MumeCore", targets: ["MumeCore"])
    ],
    targets: [
        .target(name: "MumeCore", path: "Sources/MumeCore"),
        .testTarget(
            name: "MumeCoreTests",
            dependencies: ["MumeCore"],
            path: "Tests/MumeCoreTests",
            resources: [.copy("fixtures")]
        )
    ]
)
