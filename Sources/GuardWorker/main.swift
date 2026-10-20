import Foundation
import Darwin
import GuardCore
import GuardMac

umask(0o077)
signal(SIGPIPE, SIG_IGN)
// This process must be its group's leader before it is permitted to signal that group.
guard getpgrp() == getpid() else { exit(64) }
let queue = DispatchQueue(label: "guard-worker")
var child: OwnedProcess?
var cleanup: URL?
var lastPing = DispatchTime.now().uptimeNanoseconds
var finished = false

func emit(_ event: WorkerEvent) {
    guard let data = try? JSONEncoder().encode(event) else { return }
    try? FileHandle.standardOutput.write(contentsOf: data + Data([10]))
}

func finish(_ reason: String) -> Never {
    finished = true
    let status = child?.stop()
    if let cleanup { try? FileManager.default.removeItem(at: cleanup) }
    emit(WorkerEvent(status: status, reason: reason, observedDescendants: child?.observedDescendants,
                     signalErrors: child?.descendantSignalErrors))
    // Includes this worker and same-group descendants, even after reparenting.
    kill(-getpgrp(), SIGKILL)
    exit(74)
}

let timer = DispatchSource.makeTimerSource(queue: queue)
timer.schedule(deadline: .now() + 0.25, repeating: .milliseconds(250))
timer.setEventHandler {
    if DispatchTime.now().uptimeNanoseconds - lastPing > 3_000_000_000 { finish("leaseExpired") }
}
timer.resume()

var buffer = Data()
var chunk = [UInt8](repeating: 0, count: 4096)
while true {
    let count = read(STDIN_FILENO, &chunk, chunk.count)
    if count < 0 && errno == EINTR { continue }
    if count <= 0 { queue.sync { finish("controllerEOF") } }
    buffer.append(contentsOf: chunk.prefix(count))
    if buffer.count > 65536 { queue.sync { finish("invalidFrame") } }
    while let end = buffer.firstIndex(of: 10) {
        let line = Data(buffer[..<end])
        buffer.removeSubrange(...end)
        queue.sync {
            guard !finished else { return }
            if child != nil {
                guard line == Data("ping".utf8) else { finish("invalidHeartbeat") }
                lastPing = DispatchTime.now().uptimeNanoseconds
                do { try child?.resume() }
                catch { finish("resumeFailed") }
            } else {
                do {
                    let request = try JSONDecoder().decode(WorkerRequest.self, from: line)
                    if let path = request.cleanupDirectory {
                        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
                        let temp = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
                        guard url.deletingLastPathComponent() == temp,
                              url.lastPathComponent.hasPrefix("ClaudeDont88-"),
                              UUID(uuidString: String(url.lastPathComponent.dropFirst("ClaudeDont88-".count))) != nil else {
                            finish("invalidCleanupDirectory")
                        }
                        cleanup = url
                    }
                    var output: FileHandle?
                    if let path = request.outputPath { output = try FileHandle(forWritingTo: URL(fileURLWithPath: path)) }
                    defer { try? output?.close() }
                    var rule: DetachedProcessRule?
                    if let executable = request.detachedExecutable, let argument = request.detachedArgument {
                        rule = try DetachedProcessRule(executable: URL(fileURLWithPath: executable), argument: argument)
                    } else if request.detachedExecutable != nil || request.detachedArgument != nil {
                        finish("invalidDetachedRule")
                    }
                    child = try OwnedProcess(executable: URL(fileURLWithPath: request.executable),
                        arguments: request.arguments, environment: request.environment,
                        output: output, ownsGroup: false, detachedRule: rule, resumeImmediately: false,
                        queue: queue) { finish("jobExited") }
                    lastPing = DispatchTime.now().uptimeNanoseconds
                    emit(WorkerEvent(pid: child?.pid))
                } catch { finish("launchFailed") }
            }
        }
    }
}
