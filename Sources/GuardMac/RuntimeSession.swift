import Foundation
import GuardCore

/// All methods run on queue; the pipe owner is the UI, not an unauthenticated local socket.
public final class RuntimeSession {
    public let queue: DispatchQueue
    private let emit: (RuntimeEvent) -> Void
    private var engine: WorkerProcess?
    private var task: WorkerProcess?
    private var health: WorkerProcess?
    private var directory: URL?
    private var profile: ProxyProfile?
    private var token = ""
    private var generation = UUID()
    private var conditions = LaunchConditions()
    private var timer: DispatchSourceTimer?
    private var cleanupUncertain = false
    private let environment = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
        "TMPDIR": FileManager.default.temporaryDirectory.path
    ]

    public init(queue: DispatchQueue, emit: @escaping (RuntimeEvent) -> Void) {
        self.queue = queue; self.emit = emit
    }

    public func handle(_ command: RuntimeCommand) {
        do {
            if cleanupUncertain && command.action != .stop && command.action != .ping {
                throw PolicyError.invalid("上次清理缺少完整回执，暂不创建新会话；请先核查残留进程。")
            }
            switch command.action {
            case .ping: emit(RuntimeEvent("heartbeat", "监督连接正常"))
            case .stop: stop("已关闭专用代理并强制结束本 App 管理的任务")
            case .startProxy:
                guard let profile = command.profile else { throw PolicyError.invalid("缺少代理配置") }
                try startProxy(profile, password: command.password ?? "")
            case .demo:
                guard task == nil else { throw PolicyError.invalid("已有受控任务，请先停止") }
                let epoch = generation
                task = try WorkerProcess(executable: URL(fileURLWithPath: "/bin/sh"),
                    arguments: ["-c", "/bin/sleep 600 & wait"], environment: environment, queue: queue) { [weak self] in
                        guard let self, self.generation == epoch else { return }
                        self.stop("演练进程已退出")
                    }
                emit(RuntimeEvent("demo", "不联网的守护演练正在运行，可点击“强制结束”", proxyPID: engine?.pid, taskPID: task?.pid, taskGroupID: task?.workerPID))
            case .launchCLI, .launchDesktop:
                try launch(command)
            }
        } catch {
            emit(RuntimeEvent("blocked", error.localizedDescription, proxyPID: engine?.pid, taskPID: task?.pid, taskGroupID: task?.workerPID))
        }
    }

    private func startProxy(_ profile: ProxyProfile, password: String) throws {
        guard engine == nil, task == nil else { throw PolicyError.invalid("先停止当前会话，再修改代理") }
        let token = UUID().uuidString
        let data = try profile.configuration(password: password, localToken: token)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ClaudeDont88-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let config = directory.appendingPathComponent("config.json")
        do {
            try data.write(to: config, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
            self.directory = directory; self.profile = profile; self.token = token
            let epoch = UUID()
            generation = epoch
            engine = try WorkerProcess(executable: URL(fileURLWithPath: profile.enginePath),
                arguments: ["-d", directory.path, "-f", config.path], environment: environment,
                cleanupDirectory: directory, queue: queue) { [weak self] in
                    guard let self, self.generation == epoch else { return }
                    self.stop("专用代理进程退出；受控任务已终止", fault: true)
                }
            emit(RuntimeEvent("checking", "专用代理进程已启动，正在通过代理检查美国出口", proxyPID: engine?.pid))
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 1, repeating: 15)
            timer.setEventHandler { [weak self] in self?.checkProxy(epoch: epoch) }
            self.timer = timer
            timer.resume()
        } catch {
            stop("专用代理启动失败", fault: true)
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    private func checkProxy(epoch: UUID) {
        guard epoch == generation, engine != nil, health == nil, let profile, let directory else { return }
        let resultURL = directory.appendingPathComponent("health.json")
        do {
            try Data().write(to: resultURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: resultURL.path)
            health = try WorkerProcess(executable: URL(fileURLWithPath: "/usr/bin/curl"),
                arguments: ["--silent", "--fail", "--proxy", localProxyURL(port: profile.localPort),
                            "--noproxy", "", "--proto", "=https", "--connect-timeout", "3",
                            "--max-time", "5", "--max-filesize", "65536", "https://ipwho.is/"],
                environment: environment, outputURL: resultURL, queue: queue) { [weak self] in
                    guard let self, self.generation == epoch else { return }
                    let status = self.health?.stop()
                    let uncertain = self.health?.cleanupUncertain ?? true
                    self.health = nil
                    if uncertain {
                        self.cleanupUncertain = true
                        self.stop("代理检查的清理状态未知", fault: true)
                        return
                    }
                    guard status == 0, let data = try? Data(contentsOf: resultURL), data.count <= 65536,
                          let result = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          result["success"] as? Bool == true, result["country_code"] as? String == "US" else {
                        self.stop("代理可用性或美国出口检查失败；已关闭专用代理并终止受控任务", fault: true)
                        return
                    }
                    self.conditions.proxyReady = true
                    // IP geolocation proves one request's exit, not fault-safe upstream behavior.
                    self.emit(RuntimeEvent("proxyReady", "本次出口检查为美国；系统拦截尚未验收，Claude 启动仍被锁定",
                                           proxyPID: self.engine?.pid, taskPID: self.task?.pid, taskGroupID: self.task?.workerPID))
                }
        } catch { stop("无法运行代理检查，已停止会话", fault: true) }
    }

    private func localProxyURL(port: Int) -> String { "http://guard:\(token)@127.0.0.1:\(port)" }

    private func launch(_ command: RuntimeCommand) throws {
        let desktop = command.action == .launchDesktop
        // No preference, IPC flag or installed profile can stand in for data-plane qualification.
        // shortcut: filter/identity/upstream proof adapters remain unavailable until live fault tests pass.
        try conditions.require(desktop: desktop)
        guard task == nil, let profile, let path = command.targetPath, !desktop else {
            throw PolicyError.invalid("目标无效或已有受控任务；桌面路由需单独验收")
        }
        let requirement = try CodeIdentity.compile(TargetIdentity(label: "Anthropic", requirement: ClaudeDiscovery.publisher))
        _ = try CodeIdentity.inspect(URL(fileURLWithPath: path), requiring: requirement)
        var env = environment
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env[key] = localProxyURL(port: profile.localPort)
        }
        env["NO_PROXY"] = ""; env["no_proxy"] = ""
        guard let prompt = command.prompt, !prompt.isEmpty, prompt.utf8.count <= 16384 else {
            throw PolicyError.invalid("任务内容为空或过长")
        }
        let epoch = generation
        task = try WorkerProcess(executable: URL(fileURLWithPath: path),
                                arguments: ["-p", prompt], environment: env, queue: queue) { [weak self] in
            guard let self, self.generation == epoch else { return }
            self.stop("受控任务已退出")
        }
        emit(RuntimeEvent("running", "受控任务运行中", proxyPID: engine?.pid, taskPID: task?.pid, taskGroupID: task?.workerPID))
    }

    public func stop(_ message: String, fault: Bool = false) {
        generation = UUID()
        timer?.cancel(); timer = nil
        // Close proxy channels before signalling the owned task group. This is not an OS-wide firewall.
        engine?.stop()
        health?.stop()
        task?.stop()
        cleanupUncertain = cleanupUncertain || [engine, health, task].compactMap { $0 }.contains { $0.cleanupUncertain }
        engine = nil; health = nil; task = nil
        if let directory { try? FileManager.default.removeItem(at: directory) }
        directory = nil; profile = nil; token = ""; conditions = LaunchConditions()
        if cleanupUncertain {
            emit(RuntimeEvent("cleanupUncertain", "已执行所属进程组清理，但部分守护回执缺失或后代终止失败；请核查残留进程。新会话保持锁定。"))
        } else {
            emit(RuntimeEvent(fault ? "fault" : "stopped", message))
        }
    }
}
