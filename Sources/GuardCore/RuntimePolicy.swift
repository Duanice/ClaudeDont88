import Foundation

public enum ProxyKind: String, Codable, CaseIterable {
    case http, socks5, ss, trojan
}

public struct ProxyProfile: Codable, Equatable {
    public var enginePath = "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"
    public var kind: ProxyKind = .http
    public var server = ""
    public var port = 443
    public var localPort = 17988
    public var username = ""
    public var tls = true
    public var serverName = ""
    public var cipher = "aes-128-gcm"
    public init() {}

    public func validate() throws {
        guard enginePath.hasPrefix("/"), !enginePath.utf8.contains(0),
              let address = PolicyEngine.numericAddress(server),
              !address.allSatisfy({ $0 == 0 }),
              (1...65535).contains(port), (1024...65535).contains(localPort) else {
            throw PolicyError.invalid("请选择代理内核，填写数值 IP、有效上游端口和 1024–65535 的本地端口")
        }
        guard !(PolicyEngine.numericAddress(server) == [127, 0, 0, 1] && port == localPort),
              !(server == "::1" && port == localPort) else {
            throw PolicyError.invalid("上游不能指向专用代理自身")
        }
        guard username.utf8.count <= 256, !username.contains(":"),
              !username.unicodeScalars.contains(where: { $0.value < 32 }),
              serverName.utf8.count <= 253,
              serverName.utf8.allSatisfy({ $0 == 45 || $0 == 46 || (48...57).contains($0) ||
                  (65...90).contains($0) || (97...122).contains($0) }) else {
            throw PolicyError.invalid("用户名或 TLS 服务器名不合法")
        }
        if kind == .ss, !["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"].contains(cipher) {
            throw PolicyError.invalid("不支持的 Shadowsocks 加密方式")
        }
    }

    public func configuration(password: String, localToken: String) throws -> Data {
        try validate()
        guard password.utf8.count <= 4096,
              !localToken.isEmpty, localToken.utf8.count <= 128,
              localToken.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }) else {
            throw PolicyError.invalid("代理凭据不合法")
        }
        guard !password.isEmpty || (kind != .ss && kind != .trojan && username.isEmpty) else {
            throw PolicyError.invalid("此节点需要密码")
        }
        var node: [String: Any] = ["name": "CLAUDE_ONLY", "type": kind.rawValue,
                                   "server": server, "port": port, "udp": false]
        if kind == .http || kind == .socks5 {
            node["tls"] = tls
            if !username.isEmpty { node["username"] = username; node["password"] = password }
        } else {
            node["password"] = password
            if kind == .ss { node["cipher"] = cipher }
        }
        if kind == .trojan || ((kind == .http || kind == .socks5) && tls) {
            node["skip-cert-verify"] = false
            if !serverName.isEmpty { node["sni"] = serverName }
        }
        // Construct the whole config; imported rules/providers cannot introduce DIRECT.
        let config: [String: Any] = [
            "mixed-port": localPort, "allow-lan": false, "bind-address": "127.0.0.1",
            "authentication": ["guard:\(localToken)"], "skip-auth-prefixes": [],
            "mode": "rule", "log-level": "silent", "ipv6": true,
            "external-controller": "", "external-controller-unix": "",
            "dns": ["enable": false], "tun": ["enable": false],
            "sniffer": ["enable": false], "geo-auto-update": false,
            "profile": ["store-selected": false, "store-fake-ip": false],
            "proxies": [node], "proxy-groups": [], "rules": ["MATCH,CLAUDE_ONLY"]
        ]
        return try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
    }
}

public struct LaunchConditions {
    public var proxyReady = false
    public var upstreamVerified = false
    public var identityVerified = false
    public var filterVerified = false
    public var desktopRouteVerified = false
    public init() {}

    public func failures(desktop: Bool) -> [String] {
        var reasons: [String] = []
        if !proxyReady { reasons.append("专用代理尚未通过可用性检查") }
        if !upstreamVerified { reasons.append("美国上游及无 DIRECT 回退尚未验收") }
        if !identityVerified { reasons.append("目标身份或子进程覆盖尚未验证") }
        if !filterVerified { reasons.append("缺少有效的系统流量拦截证据；已启用配置不能替代验收") }
        if desktop && !desktopRouteVerified { reasons.append("桌面 Code 的代理路径尚未验收") }
        return reasons
    }

    public func require(desktop: Bool) throws {
        let reasons = failures(desktop: desktop)
        guard reasons.isEmpty else { throw PolicyError.invalid("拒绝启动：\n" + reasons.joined(separator: "\n")) }
    }
}

public enum RuntimeAction: String, Codable { case startProxy, stop, demo, launchCLI, launchDesktop, ping }

public struct RuntimeCommand: Codable {
    public var action: RuntimeAction
    public var profile: ProxyProfile?
    public var password: String?
    public var targetPath: String?
    public var prompt: String?
    public init(_ action: RuntimeAction, profile: ProxyProfile? = nil, password: String? = nil,
                targetPath: String? = nil, prompt: String? = nil) {
        self.action = action; self.profile = profile; self.password = password
        self.targetPath = targetPath; self.prompt = prompt
    }
}

public struct RuntimeEvent: Codable {
    public var state: String
    public var message: String
    public var proxyPID: Int32?
    public var taskPID: Int32?
    public var taskGroupID: Int32?
    public init(_ state: String, _ message: String, proxyPID: Int32? = nil, taskPID: Int32? = nil, taskGroupID: Int32? = nil) {
        self.state = state; self.message = message; self.proxyPID = proxyPID; self.taskPID = taskPID
        self.taskGroupID = taskGroupID
    }
}
