import Foundation
import Darwin

public struct TargetIdentity: Codable, Equatable {
    public let label: String
    public let requirement: String

    public init(label: String, requirement: String) {
        self.label = label
        self.requirement = requirement
    }
}

public enum PolicyMode: String, Codable, CaseIterable {
    case blockAll
    case proxyOnly
}

public enum PolicyError: Error, LocalizedError {
    case invalid(String)
    public var errorDescription: String? {
        switch self { case .invalid(let reason): return reason }
    }
}

public struct GuardPolicy: Codable, Equatable {
    public let schemaVersion: Int
    public var mode: PolicyMode
    public var proxyHost: String
    public var proxyPort: Int
    public var targets: [TargetIdentity]

    public init(mode: PolicyMode = .blockAll, proxyHost: String = "127.0.0.1",
                proxyPort: Int = 7897, targets: [TargetIdentity]) {
        schemaVersion = 1
        self.mode = mode
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.targets = targets
    }

    public func validate() throws {
        guard schemaVersion == 1 else { throw PolicyError.invalid("Unsupported policy version") }
        guard proxyHost == "127.0.0.1" || proxyHost == "::1" else {
            throw PolicyError.invalid("Only the exact loopback addresses 127.0.0.1 and ::1 are accepted")
        }
        guard (1...65535).contains(proxyPort) else { throw PolicyError.invalid("Invalid proxy port") }
        guard !targets.isEmpty, targets.count <= 64 else {
            throw PolicyError.invalid("Select between 1 and 64 signed executables")
        }
        for target in targets {
            guard !target.label.isEmpty, target.label.count <= 256,
                  !target.requirement.isEmpty, target.requirement.utf8.count <= 16384 else {
                throw PolicyError.invalid("Invalid executable identity")
            }
        }
        guard Set(targets.map(\.requirement)).count == targets.count else {
            throw PolicyError.invalid("Duplicate executable identity")
        }
    }

    public static func decode(_ data: Data) throws -> GuardPolicy {
        guard data.count <= 256 * 1024 else { throw PolicyError.invalid("Policy exceeds size limit") }
        let policy = try JSONDecoder().decode(GuardPolicy.self, from: data)
        try policy.validate()
        return policy
    }
}

public enum Attribution: Equatable {
    case protected
    case other
    case unknown
}

public enum Transport: Equatable {
    case tcp
    case udp
    case other
}

public enum Decision: String {
    case allowOther
    case allowProxy
    case drop
    // Unattributed flows are an explicit coverage gap, never a successful protection verdict.
    case uncovered
}

public struct FlowDescription {
    public var attribution: Attribution
    public var host: String?
    public var port: Int?
    public var transport: Transport
    public var outbound: Bool

    public init(attribution: Attribution, host: String?, port: Int?,
                transport: Transport = .tcp, outbound: Bool = true) {
        self.attribution = attribution
        self.host = host
        self.port = port
        self.transport = transport
        self.outbound = outbound
    }
}

public enum PolicyEngine {
    public static func decide(_ flow: FlowDescription, policy: GuardPolicy?,
                              stopping: Bool = false) -> Decision {
        switch flow.attribution {
        case .other: return .allowOther
        case .unknown: return .uncovered
        case .protected: break
        }
        guard !stopping, let policy, (try? policy.validate()) != nil,
              policy.mode == .proxyOnly, flow.outbound, flow.transport == .tcp,
              flow.port == policy.proxyPort, let host = flow.host,
              let address = numericAddress(host),
              address == numericAddress(policy.proxyHost) else {
            return .drop
        }
        return .allowProxy
    }

    /// Numeric parsing avoids DNS and rejects aliases, hostnames, and integer IPv4 forms.
    public static func numericAddress(_ text: String) -> [UInt8]? {
        guard !text.contains("%"), !text.utf8.contains(0) else { return nil }
        var ipv4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return withUnsafeBytes(of: &ipv4) { Array($0) }
        }
        var ipv6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
            if bytes.prefix(12) == Array(repeating: UInt8(0), count: 10) + [255, 255] {
                return Array(bytes.suffix(4))
            }
            return bytes
        }
        return nil
    }
}
