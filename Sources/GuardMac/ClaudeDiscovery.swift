import Foundation
import GuardCore

public struct DiscoveredExecutable: Codable {
    public let path: String
    public let target: TargetIdentity
}

public struct ClaudeInventory: Codable {
    public var desktopPath: String?
    public var desktopVersion: String?
    public var executables: [DiscoveredExecutable] = []
    public var issues: [String] = []
    public var cliFound = false

    public var targets: [TargetIdentity] {
        var seen = Set<String>()
        return executables.compactMap { seen.insert($0.target.requirement).inserted ? $0.target : nil }
    }
}

public enum ClaudeDiscovery {
    // Verified against the installed Developer ID signed Claude 2.42304.2.
    static let publisher = #"anchor apple generic and certificate leaf[subject.OU] = "Q6L2SF6YDW""#
    static let desktop = publisher + #" and identifier "com.anthropic.claudefordesktop""#

    public static func scan(desktopURL: URL? = nil) -> ClaudeInventory {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        let apps = desktopURL.map { [$0] } ?? [
            URL(fileURLWithPath: "/Applications/Claude.app"),
            home.appendingPathComponent("Applications/Claude.app")
        ]
        let cliPaths = [
            home.appendingPathComponent(".local/bin/claude"),
            URL(fileURLWithPath: "/opt/homebrew/bin/claude"),
            URL(fileURLWithPath: "/usr/local/bin/claude"),
            home.appendingPathComponent(".claude/local/claude")
        ]
        return scan(apps: apps, cliPaths: cliPaths)
    }

    static func scan(apps: [URL], cliPaths: [URL]) -> ClaudeInventory {
        let fm = FileManager.default
        var result = ClaudeInventory()
        do {
            let publisherRequirement = try CodeIdentity.compile(TargetIdentity(label: "Anthropic", requirement: publisher))
            let desktopRequirement = try CodeIdentity.compile(TargetIdentity(label: "Claude", requirement: desktop))
            if let app = apps.first(where: { fm.fileExists(atPath: $0.path) })?.resolvingSymlinksInPath() {
                do {
                    _ = try CodeIdentity.inspect(app, requiring: desktopRequirement)
                    result.desktopPath = app.path
                    result.desktopVersion = Bundle(url: app)?.infoDictionary?["CFBundleShortVersionString"] as? String
                    let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey]
                    guard let enumerator = fm.enumerator(at: app, includingPropertiesForKeys: keys,
                        errorHandler: { url, error in
                            result.issues.append("\(url.lastPathComponent): \(error.localizedDescription)")
                            return true
                        }) else { throw PolicyError.invalid("无法读取 Claude 包内容") }
                    var candidates: [URL] = []
                    for case let url as URL in enumerator {
                        do {
                            let info = try url.resourceValues(forKeys: Set(keys))
                            if info.isSymbolicLink == true {
                                if !url.resolvingSymlinksInPath().path.hasPrefix(app.path + "/") {
                                    result.issues.append("未扫描包外符号链接：\(url.lastPathComponent)")
                                }
                                continue
                            }
                            if info.isRegularFile == true, fm.isExecutableFile(atPath: url.path) {
                                candidates.append(url)
                            }
                        } catch { result.issues.append("\(url.lastPathComponent): \(error.localizedDescription)") }
                    }
                    for url in candidates.sorted(by: { $0.path < $1.path }) {
                        do {
                            switch try MachOFile.kind(at: url) {
                            case .library: continue
                            case .other:
                                result.issues.append("未登记脚本或非原生程序：\(url.path.replacingOccurrences(of: app.path + "/", with: ""))")
                                continue
                            case .executable: break
                            }
                            var identity = try CodeIdentity.inspect(url, requiring: publisherRequirement)
                            // Keep the publisher constraint even if a binary declares a weaker requirement.
                            identity = TargetIdentity(label: identity.label,
                                requirement: "(\(identity.requirement)) and (\(publisher))")
                            result.executables.append(DiscoveredExecutable(path: url.path, target: identity))
                        } catch { result.issues.append("未登记 \(url.lastPathComponent): \(error.localizedDescription)") }
                    }
                } catch { result.issues.append("Claude 桌面包校验失败：\(error.localizedDescription)") }
            } else {
                result.issues.append("未找到 Claude 桌面 App")
            }
            var seen = Set<String>()
            for original in cliPaths where fm.fileExists(atPath: original.path) {
                let url = original.resolvingSymlinksInPath()
                guard seen.insert(url.path).inserted else { continue }
                do {
                    guard fm.isExecutableFile(atPath: url.path), try MachOFile.kind(at: url) == .executable else {
                        throw PolicyError.invalid("仅支持已签名的原生 CLI；不会登记通用解释器")
                    }
                    let identity = try CodeIdentity.inspect(url, requiring: publisherRequirement)
                    result.executables.append(DiscoveredExecutable(path: url.path, target: TargetIdentity(
                        label: "Claude CLI · \(identity.label)", requirement: "(\(identity.requirement)) and (\(publisher))")))
                    result.cliFound = true
                } catch { result.issues.append("CLI 未登记 \(original.path): \(error.localizedDescription)") }
            }
            if !result.cliFound { result.issues.append("未在标准安装位置找到可验证的原生 Claude CLI；自定义位置可手动添加") }
        } catch { result.issues.append(error.localizedDescription) }
        return result
    }
}
