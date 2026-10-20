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

    public init(executable: URL, arguments: [String] = [], environment: [String: String] = [:],
                output: FileHandle? = nil,
                queue: DispatchQueue, onExit: @escaping () -> Void) throws {
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
        try check(posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP |
            POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT)))
        try check(posix_spawnattr_setpgroup(&attr, 0))
        for fd in 0...2 {
            if fd == 1, let output {
                try check(posix_spawn_file_actions_adddup2(&actions, output.fileDescriptor, STDOUT_FILENO))
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
        let source = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: queue)
        self.source = source
        source.setEventHandler(handler: onExit)
        source.resume()
        guard kill(child, SIGCONT) == 0 else {
            stop()
            throw PolicyError.invalid("无法恢复受控进程")
        }
    }

    @discardableResult public func stop() -> Int32? {
        lock.lock()
        defer { lock.unlock() }
        guard !reaped else { return exitStatus }
        source?.cancel()
        source = nil
        // Keep the unreaped leader's PID reserved until after signalling its original group.
        kill(-pid, SIGKILL)
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
