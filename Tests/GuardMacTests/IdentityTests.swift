import XCTest
import Security
import Darwin
import GuardCore
@testable import GuardMac

final class IdentityTests: XCTestCase {
    func testSignedSystemBinaryCanBeRegistered() throws {
        let identity = try CodeIdentity.inspect(URL(fileURLWithPath: "/usr/bin/true"))
        XCTAssertFalse(identity.requirement.isEmpty)
        _ = try CodeIdentity.compile(identity)
    }

    func testDifferentBinariesDoNotShareIdentity() throws {
        let a = try CodeIdentity.inspect(URL(fileURLWithPath: "/usr/bin/true"))
        let b = try CodeIdentity.inspect(URL(fileURLWithPath: "/usr/bin/false"))
        XCTAssertNotEqual(a.requirement, b.requirement)
    }

    func testUnsignedScriptIsRejected() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("claude")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: url)
        XCTAssertThrowsError(try CodeIdentity.inspect(url))
    }

    func testInvalidRequirementAndAuditTokensAreRejected() throws {
        XCTAssertThrowsError(try CodeIdentity.compile(TargetIdentity(label: "invalid", requirement: "(")))
        XCTAssertNil(CodeIdentity.resolve(auditToken: Data()))
        XCTAssertNil(CodeIdentity.resolve(auditToken: Data(repeating: 0, count: 32)))
        let policy = try CompiledPolicy(GuardPolicy(targets: [
            CodeIdentity.inspect(URL(fileURLWithPath: "/usr/bin/true"))
        ]))
        XCTAssertEqual(policy.classify(appToken: nil, processToken: nil), .unknown)
    }

    func testActualAuditTokenMatchesCurrentSignedProcess() throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        XCTAssertEqual(status, KERN_SUCCESS)
        let data = withUnsafeBytes(of: &token) { Data($0) }
        let code = try XCTUnwrap(CodeIdentity.resolve(auditToken: data))
        var staticCode: SecStaticCode?
        XCTAssertEqual(SecCodeCopyStaticCode(code, [], &staticCode), errSecSuccess)
        var requirement: SecRequirement?
        XCTAssertEqual(SecCodeCopyDesignatedRequirement(try XCTUnwrap(staticCode), [], &requirement), errSecSuccess)
        let required = try XCTUnwrap(requirement)
        XCTAssertTrue(CodeIdentity.matches(code, requirement: required))
        let other = try CodeIdentity.compile(CodeIdentity.inspect(URL(fileURLWithPath: "/usr/bin/false")))
        XCTAssertFalse(CodeIdentity.matches(code, requirement: other))
        var text: CFString?
        XCTAssertEqual(SecRequirementCopyString(required, [], &text), errSecSuccess)
        let policy = try CompiledPolicy(GuardPolicy(targets: [
            TargetIdentity(label: "self", requirement: try XCTUnwrap(text) as String)
        ]))
        XCTAssertEqual(policy.classify(appToken: data, processToken: nil), .protected)
        XCTAssertEqual(policy.classify(appToken: nil, processToken: data), .protected)
    }
}
