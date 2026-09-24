// swift-tools-version: 5.9
import PackageDescription

/// BlanktickCore — the Swift mirror of the Kotlin `:core` module.
///
/// Same rule IDs, same scoring arithmetic, same hash specification, same
/// on-disk bundle format. The golden fixtures in `shared/fixtures` are run
/// against both implementations and must produce identical integers.
///
/// Like its Kotlin counterpart this target has **no dependencies at all**, so
/// nothing on its classpath is even capable of opening a socket.
let package = Package(
    name: "BlanktickCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "BlanktickCore", targets: ["BlanktickCore"])
    ],
    targets: [
        .target(name: "BlanktickCore", path: "Sources/BlanktickCore"),
        .testTarget(
            name: "BlanktickCoreTests",
            dependencies: ["BlanktickCore"],
            path: "Tests/BlanktickCoreTests",
            resources: [.copy("fixtures")]
        )
    ]
)
