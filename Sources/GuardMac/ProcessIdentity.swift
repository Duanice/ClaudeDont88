import Foundation
import Darwin
import Security

/// Includes the kernel's PID generation. Never fall back to kill(pid) for an adopted process.
public struct ProcessIdentity: Equatable {
    let bytes: Data
    public var pid: pid_t { token.val.5 == 0 ? 0 : pid_t(bitPattern: token.val.5) }
    private var token: audit_token_t {
        var result = audit_token_t()
        withUnsafeMutableBytes(of: &result) { _ = bytes.copyBytes(to: $0) }
        return result
    }

    public static func capture(_ pid: pid_t) -> ProcessIdentity? {
        guard pid > 1 else { return nil }
        var port: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &port) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, port) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(port, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS, count == 8, token.val.5 == UInt32(pid) else { return nil }
        return ProcessIdentity(bytes: withUnsafeBytes(of: token) { Data($0) })
    }

    public var isCurrent: Bool { Self.capture(pid) == self }

    public func signal(_ signal: Int32) -> Int32 {
        typealias Function = @convention(c) (UnsafeMutablePointer<audit_token_t>?, Int32) -> Int32
        // libproc interfaces vary by OS. Absence is an error, never permission to use a bare PID.
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "proc_signal_with_audittoken") else {
            return ENOTSUP
        }
        var value = token
        return unsafeBitCast(symbol, to: Function.self)(&value, signal)
    }

    func executablePath() -> String? {
        var value = token
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath_audittoken(&value, &path, UInt32(path.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath().path
    }
}

/// An exact, per-session argument is required in addition to executable path and signature.
public struct DetachedProcessRule {
    let path: String
    let argument: String
    let requirement: SecRequirement

    public init(executable: URL, argument: String) throws {
        path = executable.resolvingSymlinksInPath().path
        self.argument = argument
        requirement = try CodeIdentity.compile(CodeIdentity.inspect(executable))
    }

    func matches(_ identity: ProcessIdentity) -> Bool {
        guard identity.executablePath() == path,
              Self.arguments(identity.pid)?.contains(argument) == true,
              let code = CodeIdentity.resolve(auditToken: identity.bytes),
              CodeIdentity.matches(code, requirement: requirement) else { return false }
        return identity.isCurrent
    }

    private static func arguments(_ pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var length = 0
        guard sysctl(&mib, 3, nil, &length, nil, 0) == 0, length > 4, length <= 1_048_576 else { return nil }
        var data = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, 3, &data, &length, nil, 0) == 0 else { return nil }
        let count = data.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard (1...4096).contains(count) else { return nil }
        var cursor = 4
        while cursor < length && data[cursor] != 0 { cursor += 1 } // executable path
        while cursor < length && data[cursor] == 0 { cursor += 1 }
        var result: [String] = []
        for _ in 0..<count {
            guard cursor < length, let end = data[cursor..<length].firstIndex(of: 0) else { return nil }
            guard let text = String(bytes: data[cursor..<end], encoding: .utf8) else { return nil }
            result.append(text)
            cursor = end + 1
        }
        return result // Never parse or log environment variables.
    }
}

/// Observed descendants only. Polling cannot prove that no short-lived fork escaped observation.
final class DescendantTracker {
    private var identities: [pid_t: ProcessIdentity]
    private let root: pid_t
    private let rule: DetachedProcessRule?
    private(set) var observedCount = 0
    private(set) var signalErrors = 0

    init(root: ProcessIdentity, rule: DetachedProcessRule?) {
        identities = [root.pid: root]; self.root = root.pid; self.rule = rule
    }

    func refresh() {
        identities = identities.filter { $0.key == root || $0.value.isCurrent }
        // OwnedProcess keeps its direct child unreaped, so this one PID cannot have been reused.
        if let current = ProcessIdentity.capture(root) { identities[root] = current }
        for parent in Array(identities.values) where parent.isCurrent {
            var children = [pid_t](repeating: 0, count: 512)
            let count = proc_listchildpids(parent.pid, &children, Int32(children.count * MemoryLayout<pid_t>.size))
            guard count > 0 else { continue }
            for pid in children.prefix(min(Int(count), children.count)) where pid > 1 {
                var info = proc_bsdinfo()
                guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout.size(ofValue: info))) > 0,
                      info.pbi_ppid == UInt32(parent.pid), let child = ProcessIdentity.capture(pid) else { continue }
                var after = proc_bsdinfo()
                guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, Int32(MemoryLayout.size(ofValue: after))) > 0,
                      after.pbi_ppid == info.pbi_ppid, after.pbi_start_tvsec == info.pbi_start_tvsec,
                      after.pbi_start_tvusec == info.pbi_start_tvusec, parent.isCurrent, child.isCurrent else { continue }
                remember(child)
            }
        }
        if let rule {
            var pids = [pid_t](repeating: 0, count: 8192)
            let count = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
            for pid in pids.prefix(max(0, min(Int(count), pids.count))) where identities[pid] == nil {
                // The exact signed executable + random private session argument permits adoption after reparenting.
                var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
                guard proc_pidpath(pid, &path, UInt32(path.count)) > 0,
                      URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath().path == rule.path else { continue }
                var info = proc_bsdinfo()
                guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout.size(ofValue: info))) > 0,
                      info.pbi_uid == getuid(), let identity = ProcessIdentity.capture(pid),
                      rule.matches(identity) else { continue }
                remember(identity)
            }
        }
    }

    private func remember(_ identity: ProcessIdentity) {
        guard identities.count < 512 else { return }
        if identities[identity.pid] != identity {
            identities[identity.pid] = identity
            observedCount += 1
        }
    }

    func stop() {
        refresh()
        for (pid, identity) in identities where pid != root {
            let result = identity.signal(SIGKILL)
            if result != 0 && result != ESRCH { signalErrors += 1 }
        }
    }
}
