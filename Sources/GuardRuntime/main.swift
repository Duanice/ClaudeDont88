import Foundation
import Darwin
import GuardCore
import GuardMac

umask(0o077)
signal(SIGPIPE, SIG_IGN)
let queue = DispatchQueue(label: "io.github.duanice.ClaudeDont88.runtime")
var runtime: RuntimeSession!
var lastControl = DispatchTime.now().uptimeNanoseconds
runtime = RuntimeSession(queue: queue) { event in
    guard let data = try? JSONEncoder().encode(event) else { return }
    do {
        try FileHandle.standardOutput.write(contentsOf: data + Data([10]))
    } catch {
        queue.async {
            runtime.stop("状态连接中断，已停止会话", fault: true)
            exit(74)
        }
    }
}
let lease = DispatchSource.makeTimerSource(queue: queue)
lease.schedule(deadline: .now() + 1, repeating: .seconds(1))
lease.setEventHandler {
    if DispatchTime.now().uptimeNanoseconds - lastControl > 5_000_000_000 {
        runtime.stop("界面心跳超时，已停止会话", fault: true)
        exit(75)
    }
}
lease.resume()
var buffer = Data()
var chunk = [UInt8](repeating: 0, count: 4096)
var failed = false
while !failed {
    let size = read(STDIN_FILENO, &chunk, chunk.count)
    if size == -1 && errno == EINTR { continue }
    if size <= 0 { break }
    buffer.append(contentsOf: chunk.prefix(size))
    if buffer.count > 65536 { failed = true; break }
    while let end = buffer.firstIndex(of: 10) {
        let line = Data(buffer[..<end])
        buffer.removeSubrange(...end)
        guard let command = try? JSONDecoder().decode(RuntimeCommand.self, from: line) else {
            failed = true; break
        }
        queue.sync {
            lastControl = DispatchTime.now().uptimeNanoseconds
            runtime.handle(command)
        }
    }
}
queue.sync { runtime.stop(failed ? "控制消息无效，已停止会话" : "控制连接已关闭，已停止会话", fault: failed) }
exit(failed ? 64 : 0)
