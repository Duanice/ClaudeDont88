#!/usr/bin/env python3
"""Opt-in real Claude startup/stop test. No login, no requests forwarded, no production gate bypass."""
import argparse
import http.server
import json
import pathlib
import plistlib
import select
import subprocess
import tempfile
import threading
import time
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RejectingProxy(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_CONNECT(self):
        # Count requests only: do not retain destinations, headers, tokens, or bodies.
        type(self).requests += 1
        self.send_error(503)

    do_GET = do_CONNECT
    do_POST = do_CONNECT

    def log_message(self, *args):
        pass


def processes():
    raw = subprocess.check_output(["ps", "-axo", "pid=,ppid=,pgid=,stat=,args="], text=True)
    result = {}
    for row in raw.splitlines():
        parts = row.split(None, 4)
        if len(parts) == 5:
            pid, parent, group, state, args = parts
            result[int(pid)] = dict(parent=int(parent), group=int(group), state=state, args=args)
    return result


def event(process, timeout=15):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError("Test driver timed out")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("Test driver exited before reporting")
    return json.loads(line)


def curl(command, port):
    return subprocess.run(command + ["/usr/bin/curl", "--silent", "--show-error", "--max-time", "2",
        "--noproxy", "*", f"http://127.0.0.1:{port}/"], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=pathlib.Path, default="/Applications/Claude.app")
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--diagnostics", type=pathlib.Path, help="Local test logs; do not publish these")
    args = parser.parse_args()
    subprocess.run(["swift", "build"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    binaries = pathlib.Path(subprocess.check_output(
        ["swift", "build", "--show-bin-path"], cwd=ROOT, text=True).strip())
    before = processes()
    existing = {pid: row for pid, row in before.items()
                if row["args"].startswith(str(args.app) + "/")}
    version = plistlib.loads((args.app / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"]
    report = {"date": datetime.now().astimezone().isoformat(), "claudeVersion": version,
              "existingClaudeProcesses": len(existing), "scope": "startup-only; no login or Code task",
              "fixture": "sandbox-exec + fresh profile + mock keychain; proxy rejects every request",
              "systemLeakProtectionVerified": False}
    with tempfile.TemporaryDirectory(prefix="ClaudeDont88-real-test-") as folder:
        home = pathlib.Path(folder).resolve()
        (home / "tmp").mkdir()
        driver = home / "driver"
        subprocess.run(["swiftc", "-I", str(binaries / "Modules"),
            str(ROOT / "scripts/fixtures/claude-desktop/main.swift"),
            str(ROOT / "Sources/GuardMac/OwnedProcess.swift"),
            str(ROOT / "Sources/GuardMac/CodeIdentity.swift"),
            str(ROOT / "Sources/GuardMac/ProcessIdentity.swift"),
            *map(str, (binaries / "GuardCore.build").glob("*.swift.o")),
            "-o", str(driver)], check=True)
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RejectingProxy)
        direct = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RejectingProxy)
        for server in [proxy, direct]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        # Only this harness and its descendants get the sandbox. Existing apps are unaffected.
        # sandbox-exec is used solely as a local test fixture, not a supported product firewall.
        original_home = pathlib.Path.home()
        protected = [original_home / ".claude", original_home / "Library/Application Support/Claude",
                     original_home / "Library/Caches/Claude",
                     original_home / "Library/Preferences/com.anthropic.claudefordesktop.plist"]
        profile = '(version 1)(allow default)(deny network-outbound)'
        profile += f'(allow network-outbound (remote tcp "localhost:{proxy.server_port}"))'
        # Electron uses local IPC sockets between its processes, including anonymous sockets.
        profile += '(allow network-outbound (remote unix-socket))'
        for path in protected:
            profile += f'(deny file-read* file-write* (subpath {json.dumps(str(path))}))'
        sandbox = ["/usr/bin/sandbox-exec", "-p", profile]
        child = None
        try:
            assert curl([], direct.server_port).returncode == 0, "Direct positive control unavailable"
            assert curl(sandbox, direct.server_port).returncode != 0, "Sandbox did not block direct control"
            assert curl(sandbox, proxy.server_port).returncode == 0, "Sandbox blocked allowed proxy"
            report["networkFixtureControls"] = "passed"
            RejectingProxy.requests = 0
            child = subprocess.Popen(sandbox + [str(driver), str(args.app), str(home), str(proxy.server_port)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            started = event(child)
            assert started["state"] == "started", started
            group = started["pid"]
            assert started["pgid"] == group
            snapshots = []
            # Sample actual processes for startup; do not read user conversations or send a prompt.
            for _ in range(60):
                snapshot = processes()
                own = {pid: row for pid, row in snapshot.items()
                       if pid not in before and (row["group"] == group or
                          (str(home) in row["args"] and row["args"].startswith(str(args.app) + "/")))}
                snapshots.append(own)
                if group not in own or own[group]["state"].startswith("Z"):
                    break
                time.sleep(0.5)
            observed = {pid: row for snapshot in snapshots for pid, row in snapshot.items()}
            report["observedProcesses"] = [
                {"pid": pid, "ppid": row["parent"], "pgid": row["group"],
                 "role": "crashpad" if "chrome_crashpad_handler" in row["args"] else
                         "main" if pid == group else "helper"}
                for pid, row in observed.items()]
            report["aliveBeforeStop"] = group in snapshots[-1] and not snapshots[-1][group]["state"].startswith("Z")
            report["proxyRequestsRejected"] = RejectingProxy.requests
            report["detachedProcessesObserved"] = sum(row["group"] != group for row in observed.values())
            child.stdin.close()
            stopped = event(child)
            child.wait(timeout=5)
            report["stop"] = stopped
            stderr = (home / "stderr.log").read_text(errors="replace")
            report["sandboxInitializationFailure"] = any(
                text in stderr for text in ["sandbox initialization failed", "sandbox_init", "sandbox_apply"])
            time.sleep(1)
            after = processes()
            report["survivorsAfterStop"] = [pid for pid in observed if pid in after and
                                            not after[pid]["state"].startswith("Z")]
            report["existingClaudeProcessesPreserved"] = all(
                pid in after and after[pid]["args"] == row["args"] for pid, row in existing.items())
            report["startupAndStopPassed"] = (
                report["aliveBeforeStop"] and report["proxyRequestsRejected"] > 0 and
                stopped.get("status") == 9 and not report["survivorsAfterStop"] and
                report["existingClaudeProcessesPreserved"])
            if not report["startupAndStopPassed"]:
                report["result"] = "INCOMPLETE: process creation alone is not a successful app startup"
            else:
                report["result"] = "STARTUP_SMOKE_ONLY: authenticated Code traffic remains untested"
        finally:
            if child:
                if not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=10)
                child.stdout.close()
            for server in [proxy, direct]:
                server.shutdown()
                server.server_close()
            if args.diagnostics:
                args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
                with args.diagnostics.open("w") as out:
                    for path in [home / "chromium.log", home / "stdout.log", home / "stderr.log",
                                 home / "Library/Logs/Claude/main.log"]:
                        if not path.is_file():
                            continue
                        out.write(f"\n{path.relative_to(home)}\n")
                        out.write(path.read_text(errors="replace")[-12000:])
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    # In particular, an early app crash must not produce a green test result.
    return 0 if report.get("startupAndStopPassed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
