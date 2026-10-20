import Foundation
import Security
import Darwin
import GuardCore

/// Only signals children this object owns. The leader is not reaped until its group is stopped.
public final class OwnedProcess {
    public let pid: pid_t
    private let lock = NSLock()
    private var reaped = false
    private var exitStatus: Int32?
    private var source: DispatchSourceProcess?
    private var tracker: DescendantTracker?
    private var trackingTimer: DispatchSourceTimer?
    private let ownsGroup: Bool
    private var resumed = false
    public private(set) var observedDescendants = 0
    public private(set) var descendantSignalErrors = 0

    public init(executable: URL, arguments: [String] = [], environment: [String: String] = [:],
                input: FileHandle? = nil, output: FileHandle? = nil, errorOutput: FileHandle? = nil,
                ownsGroup: Bool = true, detachedRule: DetachedProcessRule? = nil, resumeImmediately: Bool = true,
                queue: DispatchQueue, onExit: @escaping () -> Void) throws {
        self.ownsGroup = ownsGroup
        let identity = try CodeIdentity.inspect(executable)
        let requirement = try CodeIdentity.compile(identity)
        let argv = [executable.path] + arguments
        let env = environment.map { "\($0.key)=\($0.value)" }
        guard (argv + env).allSatisfy({ !$0.utf8.contains(0) }) else { throw PolicyError.invalid("Invalid process input") }
        var attr: posix_spawnattr_t?
        var actions: posix_spawn_file_actions_t?
        func check(_ code: Int32) throws {
            if code != 0 { throw NSError(domain: NSPOSIXErrorDomain, code: Int(code)) }
        }
        try check(posix_spawnattr_init(&attr))
        defer { posix_spawnattr_destroy(&attr) }
        try check(posix_spawn_file_actions_init(&actions))
        defer { posix_spawn_file_actions_destroy(&actions) }
        try check(posix_spawnattr_setflags(&attr, Int16((ownsGroup ? POSIX_SPAWN_SETPGROUP : 0) |
            POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT)))
        if ownsGroup { try check(posix_spawnattr_setpgroup(&attr, 0)) }
        for fd in 0...2 {
            let handle = [input, output, errorOutput][fd]
            if let handle {
                try check(posix_spawn_file_actions_adddup2(&actions, handle.fileDescriptor, Int32(fd)))
            } else {
                try check(posix_spawn_file_actions_addopen(&actions, Int32(fd), "/dev/null",
                                                           fd == 0 ? O_RDONLY : O_WRONLY, 0))
            }
        }
        var args = argv.map { strdup($0) } + [nil]
        var vars = env.map { strdup($0) } + [nil]
        defer { args.forEach { free($0) }; vars.forEach { free($0) } }
        var child: pid_t = 0
        try check(posix_spawn(&child, executable.path, &actions, &attr, &args, &vars))
        pid = child
        // The suspended, unreaped child cannot be replaced by a reused PID.
        var code: SecCode?
        let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: child] as CFDictionary, [], &code)
        guard status == errSecSuccess, let code, CodeIdentity.matches(code, requirement: requirement) else {
            kill(child, SIGKILL)
            while waitpid(child, nil, 0) == -1 && errno == EINTR {}
            throw PolicyError.invalid("启动后的代码身份不匹配，已终止")
        }
        guard let identity = ProcessIdentity.capture(child) else {
            kill(child, SIGKILL)
            while waitpid(child, nil, 0) == -1 && errno == EINTR {}
            throw PolicyError.invalid("无法取得受控进程的审计身份")
        }
        tracker = DescendantTracker(root: identity, rule: detachedRule)
        let tracking = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "guard-descendants"))
        tracking.schedule(deadline: .now(), repeating: .milliseconds(50))
        tracking.setEventHandler { [weak self] in
            guard let self else { return }
            self.lock.lock()
            defer { self.lock.unlock() }
            if !self.reaped { self.tracker?.refresh() }
        }
        trackingTimer = tracking
        tracking.resume()
        let source = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: queue)
        self.source = source
        source.setEventHandler(handler: onExit)
        source.resume()
        if resumeImmediately {
            do { try resume() }
            catch { stop(); throw error }
        }
    }

    public func resume() throws {
        lock.lock()
        defer { lock.unlock() }
        guard !reaped else { throw PolicyError.invalid("受控进程已停止") }
        if resumed { return }
        guard kill(pid, SIGCONT) == 0 else { throw PolicyError.invalid("无法恢复受控进程") }
        resumed = true
    }

    @discardableResult public func stop() -> Int32? {
        lock.lock()
        defer { lock.unlock() }
        guard !reaped else { return exitStatus }
        source?.cancel()
        source = nil
        trackingTimer?.cancel(); trackingTimer = nil
        tracker?.stop()
        observedDescendants = tracker?.observedCount ?? 0
        descendantSignalErrors = tracker?.signalErrors ?? 0
        tracker = nil
        // Keep the unreaped leader's PID reserved until after signalling its original group.
        if ownsGroup { kill(-pid, SIGKILL) }
        kill(pid, SIGKILL)
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(pid, &status, 0) } while result == -1 && errno == EINTR
        if result == pid { exitStatus = status }
        reaped = true
        return exitStatus
    }

    deinit { stop() }
}
