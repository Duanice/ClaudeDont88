// Test-only driver, compiled with the production OwnedProcess and CodeIdentity sources.
// Never bundled in the app. The Python harness applies a restrictive network sandbox first.
import Foundation
import Darwin
import GuardCore

func emit(_ value: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

let args = Array(CommandLine.arguments.dropFirst())
guard args.count == 3 else { exit(64) }
let app = URL(fileURLWithPath: args[0])
let home = URL(fileURLWithPath: args[1])
let proxy = "http://127.0.0.1:\(args[2])"
do {
    let publisher = try CodeIdentity.compile(TargetIdentity(label: "Claude", requirement:
        #"anchor apple generic and certificate leaf[subject.OU] = "Q6L2SF6YDW" and identifier "com.anthropic.claudefordesktop""#))
    _ = try CodeIdentity.inspect(app, requiring: publisher)
    let outputURL = home.appendingPathComponent("stdout.log")
    FileManager.default.createFile(atPath: outputURL.path, contents: nil)
    let output = try FileHandle(forWritingTo: outputURL)
    defer { try? output.close() }
    let errorURL = home.appendingPathComponent("stderr.log")
    FileManager.default.createFile(atPath: errorURL.path, contents: nil)
    let errors = try FileHandle(forWritingTo: errorURL)
    defer { try? errors.close() }
    let crashpad = app.appendingPathComponent("Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler")
    let detached = try DetachedProcessRule(executable: crashpad,
        argument: "--database=\(home.path)/profile/Crashpad")
    let child = try OwnedProcess(executable: app.appendingPathComponent("Contents/MacOS/Claude"),
        arguments: ["--user-data-dir=\(home.path)/profile", "--proxy-server=\(proxy)",
                    "--proxy-bypass-list=<-loopback>", "--enable-logging=file",
                    "--log-file=\(home.path)/chromium.log",
                    // This fresh, never-authenticated test profile must not use the user's keychain.
                    "--use-mock-keychain"],
        environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home.path,
                      "CFFIXED_USER_HOME": home.path, "TMPDIR": home.path + "/tmp/",
                      "CLAUDE_CONFIG_DIR": home.path + "/cli",
                      "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
                      "http_proxy": proxy, "https_proxy": proxy, "NO_PROXY": "", "no_proxy": ""],
        output: output, errorOutput: errors, detachedRule: detached,
        queue: DispatchQueue(label: "claude-smoke"), onExit: {})
    emit(["state": "started", "pid": child.pid, "pgid": getpgid(child.pid)])
    // EOF also stops the owned process; an exception in the Python driver closes this pipe.
    _ = readLine()
    let began = DispatchTime.now().uptimeNanoseconds
    let status = child.stop()
    emit(["state": "stopped", "status": status as Any? ?? NSNull(),
          "observedDescendants": child.observedDescendants,
          "descendantSignalErrors": child.descendantSignalErrors,
          "leaderWaitMilliseconds": Double(DispatchTime.now().uptimeNanoseconds - began) / 1_000_000])
} catch {
    emit(["state": "error", "error": error.localizedDescription])
    exit(1)
}
