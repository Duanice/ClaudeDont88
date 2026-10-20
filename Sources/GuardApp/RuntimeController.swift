import AppKit
import SwiftUI
import GuardCore
import GuardMac

@MainActor
final class RuntimeController: ObservableObject {
    static let shared = RuntimeController()
    @Published var profile = ProxyProfile()
    @Published var password = ""
    @Published var message = "尚未启动。Claude 启动需要通过全部保护检查。"
    @Published var state = "stopped"
    @Published var proxyPID: Int32?
    @Published var taskPID: Int32?
    private var helper: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var buffer = Data()
    private var controlLost = false
    var active: Bool { proxyPID != nil || taskPID != nil || state == "checking" }

    private init() {
        do { profile = try ProfileStore.load() }
        catch { message = "无法读取已保存配置，请重新填写。" }
    }

    func chooseEngine() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "选择已安装的 mihomo 内核。不会修改 Clash Verge 配置。"
        if panel.runModal() == .OK, let url = panel.url {
            do {
                _ = try CodeIdentity.inspect(url)
                profile.enginePath = url.path
            } catch { message = "内核签名校验失败。" }
        }
    }

    private func credential() throws -> String {
        if !password.isEmpty { return password }
        return try ProfileStore.password()
    }

    func save() {
        do {
            try ProfileStore.save(profile, password: credential())
            password = ""
            message = "配置已保存，密码存入本机钥匙串。"
        } catch { message = error.localizedDescription }
    }

    func startProxy() {
        do {
            let secret = try credential()
            _ = try profile.configuration(password: secret, localToken: UUID().uuidString)
            send(RuntimeCommand(.startProxy, profile: profile, password: secret))
        } catch { message = error.localizedDescription }
    }

    func send(_ command: RuntimeCommand) {
        do {
            try ensureHelper()
            let data = try JSONEncoder().encode(command) + Data([10])
            try input?.write(contentsOf: data)
        } catch { message = "控制请求失败：\(error.localizedDescription)" }
    }

    private func ensureHelper() throws {
        guard !controlLost else {
            throw PolicyError.invalid("上次监督进程异常退出，清理状态未知。请先核查残留进程；不会用新会话覆盖这个故障。")
        }
        if helper?.isRunning == true { return }
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/guard-runtime")
        _ = try CodeIdentity.inspect(url)
        let process = Process()
        process.executableURL = url
        let control = Pipe(), events = Pipe()
        process.standardInput = control
        process.standardOutput = events
        process.standardError = FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                               "HOME": FileManager.default.homeDirectoryForCurrentUser.path]
        events.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            Task { @MainActor in self?.receive(data) }
        }
        process.terminationHandler = { [weak self] ended in
            Task { @MainActor in
                guard let self, self.helper === ended else { return }
                if self.active {
                    self.controlLost = true
                    self.message = "监督进程已退出，无法确认清理状态；Claude 启动保持锁定。"
                    self.state = "fault"
                }
                self.helper = nil
                self.input = nil
                self.output?.readabilityHandler = nil
                self.output = nil
            }
        }
        try process.run()
        try control.fileHandleForReading.close()
        try events.fileHandleForWriting.close()
        helper = process; input = control.fileHandleForWriting; output = events.fileHandleForReading
        buffer.removeAll()
    }

    private func receive(_ data: Data) {
        buffer.append(data)
        if buffer.count > 65536 { shutdown(); state = "fault"; message = "控制输出异常，已关闭控制连接"; return }
        while let end = buffer.firstIndex(of: 10) {
            let line = Data(buffer[..<end])
            buffer.removeSubrange(...end)
            guard let event = try? JSONDecoder().decode(RuntimeEvent.self, from: line) else { continue }
            state = event.state; message = event.message
            proxyPID = event.proxyPID; taskPID = event.taskPID
        }
    }

    func shutdown() {
        // EOF asks the independent helper to close the proxy and kill owned groups, even on UI exit.
        try? input?.close()
        input = nil
    }
}
