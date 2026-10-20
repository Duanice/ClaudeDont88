import XCTest
import Darwin
@testable import GuardMac

final class OwnedProcessTests: XCTestCase {
    func testOwnGroupIsKilledWithoutTouchingAnotherProcess() throws {
        let queue = DispatchQueue(label: "owned-process-test")
        let unrelated = try OwnedProcess(executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["60"], queue: queue, onExit: {})
        defer { unrelated.stop() }
        let target = try OwnedProcess(executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["60"], queue: queue, onExit: {})
        XCTAssertEqual(getpgid(target.pid), target.pid)
        XCTAssertNotEqual(getpgid(target.pid), getpgrp())
        XCTAssertNotEqual(target.stop(), 0)
        XCTAssertNotEqual(target.stop(), 0)
        XCTAssertEqual(waitpid(target.pid, nil, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
        XCTAssertEqual(kill(unrelated.pid, 0), 0)
    }

    func testExitIsObservedBeforeLeaderIsReaped() throws {
        let exited = expectation(description: "exit event")
        let target = try OwnedProcess(executable: URL(fileURLWithPath: "/usr/bin/true"),
            queue: DispatchQueue(label: "owned-exit-test"), onExit: { exited.fulfill() })
        wait(for: [exited], timeout: 3)
        // An unreaped child still reserves this PID even though it no longer executes.
        XCTAssertEqual(kill(target.pid, 0), 0)
        XCTAssertEqual(target.stop(), 0)
        XCTAssertEqual(waitpid(target.pid, nil, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }

    func testUnsignedExecutableIsRejectedBeforeLaunch() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        XCTAssertThrowsError(try OwnedProcess(executable: url,
            queue: DispatchQueue(label: "unsigned-test"), onExit: {}))
    }
}
