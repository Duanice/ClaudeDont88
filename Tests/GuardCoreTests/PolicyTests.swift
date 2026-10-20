import XCTest
@testable import GuardCore

final class PolicyTests: XCTestCase {
    private let target = TargetIdentity(label: "fixture", requirement: "identifier \"fixture\"")
    private var proxyPolicy: GuardPolicy { GuardPolicy(mode: .proxyOnly, targets: [target]) }

    func testOnlyExactProxyTCPEndpointIsPermitted() {
        for host in ["127.0.0.1", "::ffff:127.0.0.1", "::ffff:7f00:1"] {
            XCTAssertEqual(PolicyEngine.decide(
                FlowDescription(attribution: .protected, host: host, port: 7897),
                policy: proxyPolicy), .allowProxy, host)
        }
    }

    func testDirectAndAlternateLoopbackAddressesAreBlocked() {
        for host in ["1.1.1.1", "192.168.1.1", "127.0.0.2", "127.1.2.3",
                     "0.0.0.0", "::1", "2606:4700:4700::1111", "fe80::1",
                     "localhost", "127.1", "2130706433", "127.0.0.1.evil.example",
                     "[127.0.0.1]", "127.0.0.1\u{0}.example", "127.0.0.1%en0"] {
            XCTAssertEqual(PolicyEngine.decide(
                FlowDescription(attribution: .protected, host: host, port: 7897),
                policy: proxyPolicy), .drop, host)
        }
    }

    func testNoOtherPortIsAllowed() {
        for port in [0, 22, 53, 80, 443, 7896, 7898, 65535, 65536] {
            XCTAssertEqual(PolicyEngine.decide(
                FlowDescription(attribution: .protected, host: "127.0.0.1", port: port),
                policy: proxyPolicy), .drop)
        }
    }

    func testUDPAndUnknownProtocolsAreBlockedIncludingProxyPort() {
        for transport in [Transport.udp, .other] {
            XCTAssertEqual(PolicyEngine.decide(
                FlowDescription(attribution: .protected, host: "127.0.0.1", port: 7897,
                                transport: transport), policy: proxyPolicy), .drop)
        }
    }

    func testMissingEndpointAndInboundConnectionsAreBlocked() {
        for flow in [
            FlowDescription(attribution: .protected, host: nil, port: 7897),
            FlowDescription(attribution: .protected, host: "127.0.0.1", port: nil),
            FlowDescription(attribution: .protected, host: "127.0.0.1", port: 7897, outbound: false)
        ] {
            XCTAssertEqual(PolicyEngine.decide(flow, policy: proxyPolicy), .drop)
        }
    }

    func testDefaultPolicyBlocksAllTargetTraffic() {
        let policy = GuardPolicy(targets: [target])
        XCTAssertEqual(policy.mode, .blockAll)
        XCTAssertEqual(PolicyEngine.decide(
            FlowDescription(attribution: .protected, host: "127.0.0.1", port: 7897),
            policy: policy), .drop)
    }

    func testAbsentOrInvalidPolicyAndStoppingBlockTarget() {
        let flow = FlowDescription(attribution: .protected, host: "127.0.0.1", port: 7897)
        XCTAssertEqual(PolicyEngine.decide(flow, policy: nil), .drop)
        XCTAssertEqual(PolicyEngine.decide(flow, policy: proxyPolicy, stopping: true), .drop)
        var invalid = proxyPolicy
        invalid.targets = []
        XCTAssertEqual(PolicyEngine.decide(flow, policy: invalid), .drop)
    }

    func testOtherProgramsAreUnaffected() {
        XCTAssertEqual(PolicyEngine.decide(
            FlowDescription(attribution: .other, host: "1.1.1.1", port: 443),
            policy: nil, stopping: true), .allowOther)
    }

    func testMissingIdentityIsExplicitCoverageGap() {
        XCTAssertEqual(PolicyEngine.decide(
            FlowDescription(attribution: .unknown, host: "1.1.1.1", port: 443),
            policy: proxyPolicy), .uncovered)
    }

    func testIPv6ProxyDoesNotAllowIPv4() {
        let policy = GuardPolicy(mode: .proxyOnly, proxyHost: "::1", targets: [target])
        XCTAssertEqual(PolicyEngine.decide(
            FlowDescription(attribution: .protected, host: "0:0:0:0:0:0:0:1", port: 7897),
            policy: policy), .allowProxy)
        XCTAssertEqual(PolicyEngine.decide(
            FlowDescription(attribution: .protected, host: "127.0.0.1", port: 7897),
            policy: policy), .drop)
    }

    func testConfigurationRoundTrip() throws {
        XCTAssertEqual(try GuardPolicy.decode(JSONEncoder().encode(proxyPolicy)), proxyPolicy)
    }

    func testUntrustedConfigurationValidation() throws {
        var invalid = proxyPolicy
        invalid.proxyHost = "localhost"
        XCTAssertThrowsError(try invalid.validate())
        invalid = proxyPolicy
        invalid.proxyPort = 0
        XCTAssertThrowsError(try invalid.validate())
        invalid = proxyPolicy
        invalid.targets += invalid.targets
        XCTAssertThrowsError(try invalid.validate())
        invalid.targets = []
        XCTAssertThrowsError(try invalid.validate())
        invalid.targets = [TargetIdentity(label: "x", requirement: "")]
        XCTAssertThrowsError(try invalid.validate())
        let json = String(data: try JSONEncoder().encode(proxyPolicy), encoding: .utf8)!
        XCTAssertThrowsError(try GuardPolicy.decode(Data(json.replacingOccurrences(
            of: "\"schemaVersion\":1", with: "\"schemaVersion\":99").utf8)))
        XCTAssertThrowsError(try GuardPolicy.decode(Data("{}".utf8)))
        XCTAssertThrowsError(try GuardPolicy.decode(Data(repeating: 0, count: 256 * 1024 + 1)))
    }
}
