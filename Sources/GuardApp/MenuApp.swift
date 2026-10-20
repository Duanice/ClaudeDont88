import SwiftUI
import AppKit
import GuardCore
import Darwin

@main
struct GuardApp: App {
    @NSApplicationDelegateAdaptor(AppLifecycle.self) private var lifecycle
    @StateObject private var runtime = RuntimeController.shared
    @StateObject private var filter = PrototypeController()

    var body: some Scene {
        Window("ClaudeDont88 · v0.3.0", id: "dashboard") {
            TabView {
                RuntimeView(runtime: runtime).tabItem { Label("运行状态", systemImage: "shield") }
                ProxySettingsView(runtime: runtime).tabItem { Label("专用代理", systemImage: "network") }
                FilterExperimentView(model: filter).tabItem { Label("过滤实验", systemImage: "testtube.2") }
            }.padding(12).frame(minWidth: 760, minHeight: 620)
        }.defaultSize(width: 800, height: 700)
        MenuBarExtra {
            MenuContent(runtime: runtime)
        } label: {
            Label(runtime.active ? "ClaudeDont88 · 实验运行中" : "ClaudeDont88", systemImage: "exclamationmark.shield")
        }
    }
}

@MainActor
final class AppLifecycle: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { signal(SIGPIPE, SIG_IGN) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationWillTerminate(_ notification: Notification) { RuntimeController.shared.shutdown() }
}

struct MenuContent: View {
    @ObservedObject var runtime: RuntimeController
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text("v0.3.0 · 保护尚未验收")
        Text(runtime.active ? "有实验进程运行" : "没有受控任务")
        Button("打开控制面板") { NSApplication.shared.activate(); openWindow(id: "dashboard") }
        Divider()
        Button("启动专用代理", action: runtime.startProxy).disabled(runtime.active)
        Button("启动 Claude 桌面版") { runtime.send(RuntimeCommand(.launchDesktop)) }
        Button("启动 Claude CLI") { runtime.send(RuntimeCommand(.launchCLI)) }
        Button("强制结束受控任务", role: .destructive) { runtime.send(RuntimeCommand(.stop)) }
            .disabled(!runtime.active)
        Divider()
        Button("退出并停止受控任务") { NSApplication.shared.terminate(nil) }
    }
}

struct RuntimeView: View {
    @ObservedObject var runtime: RuntimeController
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Claude 启动已锁定", systemImage: "lock.shield").font(.title2.bold()).foregroundStyle(.orange)
            Text("本版本提供代理与任务管理实验。系统拦截、子进程覆盖和故障期间的保护尚未验收，因此不开放真实 Claude 任务。")
            GroupBox("会话状态") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(runtime.message).textSelection(.enabled)
                    Text(runtime.supervision).foregroundStyle(.secondary)
                    if let pid = runtime.proxyPID { Text("专用代理进程：\(pid)") }
                    if let pid = runtime.taskPID { Text("受控任务：\(pid)") }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
            }
            HStack {
                Button("启动 Claude 桌面版") { runtime.send(RuntimeCommand(.launchDesktop)) }
                Button("启动 Claude CLI") { runtime.send(RuntimeCommand(.launchCLI)) }
                Button("强制结束受控任务", role: .destructive) { runtime.send(RuntimeCommand(.stop)) }
                    .disabled(!runtime.active)
            }
            Text("停止覆盖本 App 创建的进程组和已登记的子进程；完整后代覆盖尚未验收。从其他位置启动的 Claude 不会自动被接管。")
                .font(.callout).foregroundStyle(.secondary)
            Divider()
            Text("本地停止演练").font(.headline)
            Text("创建不联网的测试任务和独立守护进程。监督进程失联或卡死超过约 3 秒时，守护进程会结束本组任务。")
            Button("启动不联网演练") { runtime.send(RuntimeCommand(.demo)) }
                .disabled(runtime.taskPID != nil)
                .accessibilityLabel("启动不联网演练")
            Text("菜单栏会在关闭窗口后继续运行；选择“退出并停止受控任务”才会退出 App。")
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
        }.padding(20)
    }
}

struct ProxySettingsView: View {
    @ObservedObject var runtime: RuntimeController
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("专用代理配置").font(.title2.bold())
                Text("启动独立 mihomo 进程，只使用一个上游节点。配置中没有 DIRECT 回退，不修改系统代理、Clash Verge 或时区。")
                Form {
                    HStack {
                        TextField("内核路径", text: $runtime.profile.enginePath)
                        Button("选择…", action: runtime.chooseEngine)
                    }
                    Picker("上游协议", selection: $runtime.profile.kind) {
                        Text("HTTP / HTTPS").tag(ProxyKind.http)
                        Text("SOCKS5").tag(ProxyKind.socks5)
                        Text("Shadowsocks").tag(ProxyKind.ss)
                        Text("Trojan").tag(ProxyKind.trojan)
                    }
                    TextField("节点数值 IP", text: $runtime.profile.server)
                    TextField("上游端口", value: $runtime.profile.port, format: .number.grouping(.never))
                    TextField("本地专用端口", value: $runtime.profile.localPort, format: .number.grouping(.never))
                    if runtime.profile.kind == .http || runtime.profile.kind == .socks5 {
                        TextField("用户名（可选）", text: $runtime.profile.username)
                        Toggle("上游使用 TLS", isOn: $runtime.profile.tls)
                    }
                    SecureField("密码（留空沿用已保存值）", text: $runtime.password)
                    if runtime.profile.kind == .ss {
                        Picker("加密方式", selection: $runtime.profile.cipher) {
                            ForEach(["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                                     "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"], id: \.self) { Text($0).tag($0) }
                        }
                    } else {
                        TextField("TLS 服务器名（按节点提供的信息填写）", text: $runtime.profile.serverName)
                    }
                }.disabled(runtime.active)
                HStack {
                    Button("保存到本机", action: runtime.save).disabled(runtime.active)
                    Button("启动专用代理", action: runtime.startProxy).disabled(runtime.active)
                    Button("停止代理与受控任务") { runtime.send(RuntimeCommand(.stop)) }.disabled(!runtime.active)
                }
                Text(runtime.message).textSelection(.enabled)
                Text("密码保存到钥匙串；运行时会暂存在仅当前用户可读的配置文件中，正常停止后删除。每 15 秒经专用代理访问 ipwho.is 检查美国出口，失败就停止会话。IP 位置检查不等于防泄漏验收。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("不支持直接粘贴订阅链接。若上游填写现有本地代理，它自身的 DIRECT 规则仍可能影响出口，不能据此认定固定了美国节点。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(20)
        }
    }
}
