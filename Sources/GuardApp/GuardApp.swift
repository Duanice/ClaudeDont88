import SwiftUI
import AppKit
import NetworkExtension
import SystemExtensions
import GuardCore
import GuardMac

struct FilterExperimentView: View {
    @ObservedObject var model: PrototypeController

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label("实验原型 · 尚未通过防泄漏验收", systemImage: "exclamationmark.shield")
                    .font(.title2.bold()).foregroundStyle(.orange)
                Text("此页用于签名与过滤实验。系统过滤器尚未通过实机防泄漏验收；身份登记不等于保护已生效。")
                    .fixedSize(horizontal: false, vertical: true)
                GroupBox("测试策略") {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker("模式", selection: $model.mode) {
                            Text("阻断目标程序的全部网络").tag(PolicyMode.blockAll)
                            Text("仅允许指定本地 TCP 端点").tag(PolicyMode.proxyOnly)
                        }
                        HStack {
                            Picker("地址", selection: $model.host) {
                                Text("127.0.0.1").tag("127.0.0.1")
                                Text("::1").tag("::1")
                            }
                            TextField("端口", text: $model.port).frame(width: 85)
                        }
                        Text("端点可达不代表经过美国节点；必须另行验证代理上游。")
                            .font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Button("扫描已安装的 Claude", action: model.discoverClaude)
                            Button("添加已签名程序…", action: model.chooseTarget)
                            Button("添加内置测试程序", action: model.addProbe)
                            Button("清空") { model.targets = [] }
                        }
                        if !model.targets.isEmpty {
                            ScrollView {
                                VStack(alignment: .leading) {
                                    ForEach(model.targets, id: \.requirement) { target in
                                        Text(target.label).font(.system(.body, design: .monospaced))
                                    }
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }.frame(height: 110)
                        }
                        if model.targets.isEmpty {
                            Text("未选择目标。扫描可登记桌面包内的原生程序及标准位置的原生 CLI。").foregroundStyle(.secondary)
                        }
                    }.padding(6)
                }
                .disabled(model.configurationEnabled || model.busy)

                HStack {
                    Button("1. 请求加载系统扩展", action: model.activate)
                        .disabled(!model.provisioned || model.busy)
                    Button("2. 启用测试过滤", action: model.enable)
                        .disabled(!model.provisioned || model.targets.isEmpty ||
                                  model.configurationEnabled || model.busy)
                    Button("刷新配置状态", action: model.refresh).disabled(model.busy)
                }
                if !model.provisioned {
                    Text("当前包没有系统扩展描述文件，仅可查看原型。实机加载需要相应的 Apple 开发者签名和权限。")
                        .foregroundStyle(.orange)
                }
                Text(model.configurationEnabled ?
                     "系统配置：已启用；实际流量拦截仍需独立测试。" :
                     "系统配置：未启用或无法读取。")
                    .font(.headline)
                Text(model.message).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if let inventory = model.inventory {
                    DisclosureGroup("扫描详情 · \(inventory.executables.count) 个程序 / \(inventory.targets.count) 个签名身份") {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 5) {
                                Text("桌面版：\(inventory.desktopVersion ?? "未验证")；CLI：\(inventory.cliFound ? "已找到" : "未找到")")
                                ForEach(inventory.executables.indices, id: \.self) { i in
                                    Text(inventory.executables[i].path).textSelection(.enabled)
                                }
                                ForEach(inventory.issues.indices, id: \.self) { i in
                                    Text(inventory.issues[i]).foregroundStyle(.orange).textSelection(.enabled)
                                }
                                Text("清单不覆盖运行时下载的程序、任意子进程、虚拟机或远程任务。")
                            }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                        }.frame(height: 130)
                    }
                }
                Spacer(minLength: 0)
                HStack {
                    Button("停用测试过滤", action: { model.showDisableConfirmation = true })
                        .disabled(!model.configurationEnabled || model.busy)
                    Spacer()
                    Text("无真实 Claude 任务时再开展测试").font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(24).frame(minWidth: 680, minHeight: 530)
            .confirmationDialog("停用后，测试目标将恢复正常联网。请先关闭所有测试进程。",
                                isPresented: $model.showDisableConfirmation) {
                Button("停用测试过滤", role: .destructive, action: model.disable)
            }
            .task { model.refresh() }
        }
    }
}

@MainActor
final class PrototypeController: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    static let extensionID = "io.github.duanice.ClaudeDont88.filter"
    @Published var mode: PolicyMode = .blockAll
    @Published var host = "127.0.0.1"
    @Published var port = "7897"
    @Published var targets: [TargetIdentity] = []
    @Published var message = "默认不安装、不启用过滤器。"
    @Published var configurationEnabled = false
    @Published var busy = false
    @Published var showDisableConfirmation = false
    @Published var inventory: ClaudeInventory?
    private let manager = NEFilterManager.shared()

    var provisioned: Bool {
        let root = Bundle.main.bundleURL
        return FileManager.default.fileExists(atPath: root.appendingPathComponent(
            "Contents/embedded.provisionprofile").path) &&
            FileManager.default.fileExists(atPath: root.appendingPathComponent(
                "Contents/Library/SystemExtensions/\(Self.extensionID).systemextension/Contents/embedded.provisionprofile").path)
    }

    func chooseTarget() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.message = "选择具体的已签名 App 或可执行文件；不按进程名匹配。"
        if panel.runModal() == .OK { panel.urls.forEach(addTarget) }
    }

    func addProbe() {
        addTarget(Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/guard-probe"))
    }

    func discoverClaude() {
        guard !busy, !configurationEnabled else { return }
        busy = true
        message = "正在验证 Claude 及包内程序的签名…"
        Task {
            let found = await Task.detached(priority: .userInitiated) { ClaudeDiscovery.scan() }.value
            inventory = found
            var merged = targets
            for target in found.targets where !merged.contains(where: { $0.requirement == target.requirement }) {
                merged.append(target)
            }
            if merged.count > 64 {
                message = "扫描得到的身份超过 64 个，未更改目标清单。"
            } else {
                targets = merged
                message = "扫描完成：\(found.executables.count) 个程序，\(found.targets.count) 个签名身份。" +
                    (found.issues.isEmpty ? "" : "另有 \(found.issues.count) 项未覆盖，见扫描详情。") +
                    "登记不代表已启用网络保护。"
            }
            busy = false
        }
    }

    private func addTarget(_ url: URL) {
        do {
            let identity = try CodeIdentity.inspect(url)
            guard !targets.contains(where: { $0.requirement == identity.requirement }) else { return }
            guard targets.count < 64 else { throw PolicyError.invalid("最多选择 64 个程序") }
            targets.append(identity)
            message = "已登记签名：\(identity.label)。更新二进制后请重新核对。"
        } catch { message = error.localizedDescription }
    }

    func refresh() {
        // Ad-hoc preview builds do not query privileged Network Extension preferences.
        guard provisioned else { message = "预览构建：网络系统扩展未加载。"; return }
        busy = true
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                self.busy = false
                if let error { self.message = error.localizedDescription; return }
                self.configurationEnabled = self.manager.isEnabled
                if let data = self.manager.providerConfiguration?.vendorConfiguration?["policy"] as? Data,
                   let policy = try? GuardPolicy.decode(data) {
                    self.mode = policy.mode
                    self.host = policy.proxyHost
                    self.port = String(policy.proxyPort)
                    self.targets = policy.targets
                }
                self.message = "配置状态已读取；这不等于扩展已拦截流量。请执行独立探针测试。"
            }
        }
    }

    func activate() {
        guard provisioned else { return }
        guard Bundle.main.bundleURL.path.hasPrefix("/Applications/") else {
            message = "请先把已正确签名的 App 放入 /Applications。"
            return
        }
        busy = true
        message = "正在请求系统扩展；macOS 可能要求在系统设置中授权。"
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func enable() {
        guard provisioned, !busy else { return }
        do {
            guard let portNumber = Int(port) else { throw PolicyError.invalid("端口必须是整数") }
            let policy = GuardPolicy(mode: mode, proxyHost: host, proxyPort: portNumber, targets: targets)
            _ = try CompiledPolicy(policy)
            let data = try JSONEncoder().encode(policy)
            busy = true
            manager.loadFromPreferences { error in
                DispatchQueue.main.async {
                    if let error { self.finish(error); return }
                    guard !self.manager.isEnabled else {
                        self.busy = false
                        self.message = "请先结束测试并停用旧配置，再修改策略。"
                        return
                    }
                    let config = NEFilterProviderConfiguration()
                    config.filterSockets = true
                    config.filterDataProviderBundleIdentifier = Self.extensionID
                    config.vendorConfiguration = ["policy": data]
                    self.manager.providerConfiguration = config
                    self.manager.localizedDescription = "ClaudeDont88 v0.2.0 实验过滤器"
                    self.manager.isEnabled = true
                    self.manager.saveToPreferences { error in
                        DispatchQueue.main.async { self.finish(error) }
                    }
                }
            }
        } catch { message = error.localizedDescription }
    }

    func disable() {
        guard provisioned, !busy else { return }
        busy = true
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                if let error { self.finish(error); return }
                self.manager.isEnabled = false
                self.manager.saveToPreferences { error in
                    DispatchQueue.main.async { self.finish(error) }
                }
            }
        }
    }

    private func finish(_ error: Error?) {
        busy = false
        if let error { message = error.localizedDescription } else { refresh() }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            message = "等待系统授权：系统设置 → 通用 → 登录项与扩展 → 网络扩展。"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            busy = false
            message = result == .completed ?
                "系统扩展请求完成。下一步启用测试过滤；仍需验证实际拦截。" :
                "系统扩展操作需要重启后完成。当前不能确认拦截。"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            busy = false
            message = "扩展未加载：\(error.localizedDescription)"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        // Replacing a running filter can create a coverage gap. Stop the experiment first.
        .cancel
    }
}
