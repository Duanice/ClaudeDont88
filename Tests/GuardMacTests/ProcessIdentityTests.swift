import XCTest
import Darwin
@testable import GuardMac

final class ProcessIdentityTests: XCTestCase {
    func testInvalidPIDsAreRejected() {
        XCTAssertNil(ProcessIdentity.capture(0))
        XCTAssertNil(ProcessIdentity.capture(1))
        XCTAssertNil(ProcessIdentity.capture(-1))
    }

    func testStaleGenerationCannotSignalCurrentProcess() throws {
        let child = try OwnedProcess(executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["60"], queue: DispatchQueue(label: "audit-test"), onExit: {})
        defer { child.stop() }
        let identity = try XCTUnwrap(ProcessIdentity.capture(child.pid))
        var bytes = identity.bytes
        bytes[28] ^= 1
        let stale = ProcessIdentity(bytes: bytes)
        XCTAssertEqual(stale.signal(SIGKILL), ESRCH)
        XCTAssertTrue(identity.isCurrent)
        XCTAssertEqual(identity.signal(SIGCONT), 0)
        XCTAssertEqual(identity.signal(SIGKILL), 0)
        XCTAssertEqual(child.stop(), SIGKILL)
        XCTAssertFalse(identity.isCurrent)
    }

    func testAdoptionRequiresExactArgumentAndSignedExecutable() throws {
        let executable = URL(fileURLWithPath: "/bin/sleep")
        let child = try OwnedProcess(executable: executable, arguments: ["60"],
            queue: DispatchQueue(label: "adoption-test"), onExit: {})
        defer { child.stop() }
        let identity = try XCTUnwrap(ProcessIdentity.capture(child.pid))
        XCTAssertTrue(try DetachedProcessRule(executable: executable, argument: "60").matches(identity))
        XCTAssertFalse(try DetachedProcessRule(executable: executable, argument: "6").matches(identity))
        XCTAssertFalse(try DetachedProcessRule(executable: URL(fileURLWithPath: "/bin/sh"), argument: "60").matches(identity))
    }

    func testAdoptionNormalizesPrivateVarAlias() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let executable = folder.appendingPathComponent("sleep")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/sleep"), to: executable)
        let child = try OwnedProcess(executable: executable, arguments: ["60"],
            queue: DispatchQueue(label: "alias-test"), onExit: {})
        defer { child.stop() }
        let identity = try XCTUnwrap(ProcessIdentity.capture(child.pid))
        XCTAssertTrue(try DetachedProcessRule(executable: executable, argument: "60").matches(identity))
    }
}
