// swift-tools-version: 5.9
// NLITPv8 - Network Layer for Intelligent Transport Protocol
//
// Copyright © 2025 Fortified Solutions Inc.

import PackageDescription

let package = Package(
    name: "NLITP",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "NLITP",
            targets: ["NLITP"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0")
    ],
    targets: [
        .target(
            name: "NLITP",
            dependencies: [
                .product(name: "Logging", package: "swift-log")
            ]
        )
    ]
)
