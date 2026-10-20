import XCTest
import GuardCore
@testable import GuardMac

final class DiscoveryTests: XCTestCase {
    private func withFile<T>(_ bytes: [UInt8], _ body: (URL) throws -> T) throws -> T {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        return try body(url)
    }

    private func integer(_ value: UInt64, bytes: Int = 4, little: Bool = false) -> [UInt8] {
        let result = (0..<bytes).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        return little ? result.reversed() : result
    }

    private func thin(type: UInt64 = 2, little: Bool = true, is64: Bool = true) -> [UInt8] {
        integer(is64 ? 0xfeedfacf : 0xfeedface, little: little) +
            [UInt8](repeating: 0, count: 8) + integer(type, little: little)
    }

    private func fat(_ slices: [[UInt8]], is64: Bool = false, little: Bool = false) -> [UInt8] {
        var data = integer(is64 ? 0xcafebabf : 0xcafebabe, little: little) +
            integer(UInt64(slices.count), little: little)
        var offset = 8 + slices.count * (is64 ? 32 : 20)
        for slice in slices {
            data += [UInt8](repeating: 0, count: 8)
            data += integer(UInt64(offset), bytes: is64 ? 8 : 4, little: little)
            data += integer(UInt64(slice.count), bytes: is64 ? 8 : 4, little: little)
            data += [UInt8](repeating: 0, count: is64 ? 8 : 4)
            offset += slice.count
        }
        return data + slices.flatMap { $0 }
    }

    func testThinExecutablesAndLibraries() throws {
        for little in [true, false] {
            for is64 in [true, false] {
                for type: UInt64 in [2, 6, 8] {
                    try withFile(thin(type: type, little: little, is64: is64)) {
                        XCTAssertEqual(try MachOFile.kind(at: $0), type == 2 ? .executable : .library)
                    }
                }
            }
        }
    }

    func testUniversalExecutablesAndLibraries() throws {
        for little in [true, false] {
            for is64 in [true, false] {
                try withFile(fat([thin(), thin(little: false)], is64: is64, little: little)) {
                    XCTAssertEqual(try MachOFile.kind(at: $0), .executable)
                }
                try withFile(fat([thin(type: 6), thin(type: 6)], is64: is64, little: little)) {
                    XCTAssertEqual(try MachOFile.kind(at: $0), .library)
                }
            }
        }
    }

    func testMalformedAndMixedHeadersAreRejected() throws {
        var overflowing = fat([thin()], is64: true)
        overflowing.replaceSubrange(16..<24, with: integer(UInt64.max, bytes: 8))
        var overlapsTable = fat([thin()])
        overlapsTable.replaceSubrange(16..<20, with: integer(8))
        for bytes in [
            Array(thin().prefix(10)), Array(fat([thin()]).dropLast()),
            integer(0xcafebabe) + integer(65), integer(0xcafebabe) + integer(0),
            fat([thin(), thin(type: 6)]), overflowing, overlapsTable
        ] {
            try withFile(bytes) { XCTAssertThrowsError(try MachOFile.kind(at: $0)) }
        }
    }

    func testScriptsAreNotNativeExecutables() throws {
        for bytes in [[], [0], Array("#!/bin/sh\nexit 0\n".utf8)] as [[UInt8]] {
            try withFile(bytes) { XCTAssertEqual(try MachOFile.kind(at: $0), .other) }
        }
    }

    func testActualSystemBinaryIsExecutableButNotAnthropic() throws {
        let url = URL(fileURLWithPath: "/usr/bin/true")
        XCTAssertEqual(try MachOFile.kind(at: url), .executable)
        let required = try CodeIdentity.compile(TargetIdentity(label: "publisher", requirement: ClaudeDiscovery.publisher))
        XCTAssertThrowsError(try CodeIdentity.inspect(url, requiring: required))
    }

    func testDiscoveryRejectsUnrelatedSignedCode() {
        let result = ClaudeDiscovery.scan(apps: [URL(fileURLWithPath: "/usr/bin/true")],
                                         cliPaths: [URL(fileURLWithPath: "/usr/bin/false")])
        XCTAssertNil(result.desktopPath)
        XCTAssertFalse(result.cliFound)
        XCTAssertTrue(result.executables.isEmpty)
        XCTAssertGreaterThanOrEqual(result.issues.count, 2)
    }

    func testMissingInstallationsAreReported() {
        let result = ClaudeDiscovery.scan(apps: [], cliPaths: [])
        XCTAssertTrue(result.executables.isEmpty)
        XCTAssertEqual(result.issues.count, 2)
        XCTAssertFalse(result.cliFound)
    }

    func testTargetsDeduplicateByRequirementNotName() {
        var result = ClaudeInventory()
        result.executables = [
            DiscoveredExecutable(path: "/a", target: TargetIdentity(label: "helper", requirement: "A")),
            DiscoveredExecutable(path: "/b", target: TargetIdentity(label: "other helper", requirement: "A")),
            DiscoveredExecutable(path: "/c", target: TargetIdentity(label: "helper", requirement: "B"))
        ]
        XCTAssertEqual(result.targets.map(\.requirement), ["A", "B"])
    }
}
