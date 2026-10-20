import XCTest
@testable import GuardCore

final class RuntimePolicyTests: XCTestCase {
    private var profile: ProxyProfile {
        var p = ProxyProfile(); p.server = "203.0.113.20"; return p
    }

    func testEveryProtocolHasExactlyOneUpstreamAndNoFallbackOrSystemRouting() throws {
        for kind in ProxyKind.allCases {
            var p = profile; p.kind = kind
            let config = try XCTUnwrap(JSONSerialization.jsonObject(
                with: p.configuration(password: "test-only", localToken: "test-token")) as? [String: Any])
            XCTAssertEqual(config["rules"] as? [String], ["MATCH,CLAUDE_ONLY"])
            XCTAssertEqual((config["proxies"] as? [[String: Any]])?.count, 1)
            XCTAssertEqual((config["proxy-groups"] as? [Any])?.count, 0)
            XCTAssertEqual(config["allow-lan"] as? Bool, false)
            XCTAssertEqual(config["bind-address"] as? String, "127.0.0.1")
            XCTAssertEqual(config["authentication"] as? [String], ["guard:test-token"])
            XCTAssertEqual((config["skip-auth-prefixes"] as? [String])?.count, 0)
            XCTAssertEqual((config["tun"] as? [String: Bool])?["enable"], false)
            XCTAssertEqual((config["dns"] as? [String: Bool])?["enable"], false)
            XCTAssertEqual(config["external-controller"] as? String, "")
            XCTAssertNil(config["proxy-providers"])
        }
    }

    func testInvalidEndpointsCredentialsAndCipherAreRejected() {
        for host in ["", "example.com", "127.0.0.1\nrules:", "0.0.0.0", "::", "1.2.3.4\0"] {
            var p = profile; p.server = host
            XCTAssertThrowsError(try p.validate())
        }
        for port in [-1, 0, 65536] {
            var p = profile; p.port = port; XCTAssertThrowsError(try p.validate())
        }
        for host in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            var p = profile; p.server = host; p.port = p.localPort
            XCTAssertThrowsError(try p.validate())
        }
        var p = profile; p.kind = .ss; p.cipher = "none"
        XCTAssertThrowsError(try p.configuration(password: "x", localToken: "token"))
        p = profile
        XCTAssertThrowsError(try p.configuration(password: "", localToken: "bad:token"))
        p.username = "user"
        XCTAssertThrowsError(try p.configuration(password: "", localToken: "token"))
        for name in ["bad/name", "bad\nname", "bad:name"] {
            p = profile; p.serverName = name
            XCTAssertThrowsError(try p.validate())
        }
    }

    func testTLSVerificationCannotBeDisabledByProfile() throws {
        var p = profile; p.serverName = "proxy.example.com"
        for kind in [ProxyKind.http, .socks5, .trojan] {
            p.kind = kind
            let config = try XCTUnwrap(JSONSerialization.jsonObject(
                with: p.configuration(password: "fixture", localToken: "token")) as? [String: Any])
            let node = try XCTUnwrap((config["proxies"] as? [[String: Any]])?.first)
            XCTAssertEqual(node["skip-cert-verify"] as? Bool, false)
        }
    }

    func testSavedProfileHasNoPasswordsOrLocalToken() throws {
        let data = try JSONEncoder().encode(profile)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(fields["password"])
        XCTAssertNil(fields["token"])
        XCTAssertEqual(try JSONDecoder().decode(ProxyProfile.self, from: data), profile)
    }

    func testLaunchGateRequiresEveryApplicableCondition() {
        for flags in 0..<32 {
            var c = LaunchConditions()
            c.proxyReady = flags & 1 != 0; c.upstreamVerified = flags & 2 != 0
            c.identityVerified = flags & 4 != 0; c.filterVerified = flags & 8 != 0
            c.desktopRouteVerified = flags & 16 != 0
            XCTAssertEqual(c.failures(desktop: false).isEmpty, flags & 15 == 15)
            XCTAssertEqual(c.failures(desktop: true).isEmpty, flags == 31)
        }
        XCTAssertThrowsError(try LaunchConditions().require(desktop: false))
    }
}
