import Foundation
import Darwin
import GuardCore

/// The worker owns the job; losing this controller's pipe or lease makes the worker stop its group.
public final class WorkerProcess {
    public private(set) var pid: pid_t = 0
    public var workerPID: pid_t { worker?.pid ?? 0 }
    public private(set) var cleanupUncertain = false
    private var worker: OwnedProcess?
    private let input: FileHandle
    private let output: FileHandle
    private var heartbeat: DispatchSourceTimer?
    private var stopped = false
    private var status: Int32?
    private let cleanupDirectory: URL?

    public init(executable: URL, arguments: [String] = [], environment: [String: String],
                outputURL: URL? = nil, cleanupDirectory: URL? = nil,
                queue: DispatchQueue, onExit: @escaping () -> Void) throws {
        self.cleanupDirectory = cleanupDirectory
        let control = Pipe(), events = Pipe()
        input = control.fileHandleForWriting; output = events.fileHandleForReading
        let runtime = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let helper = runtime.deletingLastPathComponent().appendingPathComponent("guard-worker")
        worker = try OwnedProcess(executable: helper, environment: environment,
            input: control.fileHandleForReading, output: events.fileHandleForWriting, queue: queue,
            onExit: onExit)
        try control.fileHandleForReading.close()
        try events.fileHandleForWriting.close()
        do {
            let request = WorkerRequest(executable: executable.path, arguments: arguments, environment: environment,
                                        outputPath: outputURL?.path, cleanupDirectory: cleanupDirectory?.path)
            let data = try JSONEncoder().encode(request)
            guard data.count <= 65536 else { throw PolicyError.invalid("守护请求过长") }
            try input.write(contentsOf: data + Data([10]))
            guard let event = readEvent(timeout: 5), let pid = event.pid, pid > 1 else {
                throw PolicyError.invalid("任务守护进程未完成启动")
            }
            self.pid = pid
            // The job stays suspended until the controller has received its identity.
            try input.write(contentsOf: Data("ping\n".utf8))
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(500))
            timer.setEventHandler { [weak self] in
                guard let self, !self.stopped else { return }
                do { try self.input.write(contentsOf: Data("ping\n".utf8)) }
                catch { onExit() }
            }
            heartbeat = timer; timer.resume()
        } catch {
            stop()
            throw error
        }
    }

    private func readEvent(timeout: Double) -> WorkerEvent? {
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
        var bytes = Data()
        while bytes.count <= 65536 && DispatchTime.now().uptimeNanoseconds < deadline {
            var fd = pollfd(fd: output.fileDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
            let result = poll(&fd, 1, 50)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { return nil }
            if result == 0 { continue }
            var byte: UInt8 = 0
            guard read(output.fileDescriptor, &byte, 1) == 1 else { return nil }
            if byte == 10 { return try? JSONDecoder().decode(WorkerEvent.self, from: bytes) }
            bytes.append(byte)
        }
        return nil
    }

    @discardableResult public func stop() -> Int32? {
        guard !stopped else { return status }
        stopped = true
        heartbeat?.cancel(); heartbeat = nil
        try? input.close()
        // Give the worker time to reap the job and remove its private files. Its own lease is independent.
        let report = readEvent(timeout: 1)
        status = report?.status
        worker?.stop() // reserved worker PID makes this group kill safe even if the worker already exited
        cleanupUncertain = report?.status == nil || report?.signalErrors != 0 ||
            (worker?.descendantSignalErrors ?? 0) != 0
        worker = nil
        try? output.close()
        if let cleanupDirectory { try? FileManager.default.removeItem(at: cleanupDirectory) }
        return status
    }

    deinit { stop() }
}
