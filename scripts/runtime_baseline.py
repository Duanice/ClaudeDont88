#!/usr/bin/env python3
"""Exercise real owned processes and local proxy fixtures, never launch Claude."""
import argparse
import contextlib
import http.server
import json
import os
import pathlib
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time


def until(check, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for fixture")


def members(group):
    rows = subprocess.check_output(["ps", "-axo", "pid=,pgid=,stat="], text=True)
    return [(int(pid), state) for pid, pgid, state in (r.split() for r in rows.splitlines())
            if int(pgid) == group]


def stopped(group):
    return all(state.startswith("Z") for _, state in members(group))


class Runtime:
    def __init__(self, binary):
        self.proc = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0)
        self.buffer = b""

    def send(self, action, **fields):
        self.proc.stdin.write(json.dumps(dict(action=action, **fields)).encode() + b"\n")
        self.proc.stdin.flush()

    def event(self, expected, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                event = json.loads(line)
                if event["state"] == expected:
                    return event
                continue
            if select.select([self.proc.stdout], [], [], 0.1)[0]:
                chunk = os.read(self.proc.stdout.fileno(), 4096)
                assert chunk, "Runtime exited without expected event"
                self.buffer += chunk
        raise AssertionError("Missing runtime state: " + expected)

    def demo(self):
        self.send("demo")
        group = self.event("demo")["taskPID"]
        until(lambda: len(members(group)) >= 2)
        return group

    def close(self):
        if not self.proc.stdin.closed:
            self.proc.stdin.close()
        self.proc.wait(timeout=5)
        self.proc.stdout.close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def runtime_cases(binary):
    results = []
    r = Runtime(binary)
    try:
        for action in ["launchCLI", "launchDesktop"]:
            r.send(action, filterVerified=True, upstreamVerified=True, identityVerified=True,
                   targetPath="/usr/bin/true", prompt="fixture")
            event = r.event("blocked")
            assert "拒绝启动" in event["message"] and event.get("taskPID") is None
        results.append("IPC cannot bypass launch gate")
        group = r.demo()
        r.send("stop")
        r.event("stopped")
        until(lambda: stopped(group))
        results.append("SIGKILL stops leader and same-group child")
        group = r.demo()
    finally:
        r.close()
    until(lambda: stopped(group))
    results.append("controller EOF cleans process group")
    r = Runtime(binary)
    try:
        group = r.demo()
        r.send("unknown")
        r.proc.wait(timeout=5)
        assert r.proc.returncode == 64
        until(lambda: stopped(group))
        results.append("invalid command stops active session")
    finally:
        r.close()
    r = Runtime(binary)
    try:
        group = r.demo()
        r.proc.stdout.close()
        r.send("launchCLI")
        r.proc.wait(timeout=5)
        assert r.proc.returncode == 74
        until(lambda: stopped(group))
        results.append("broken status pipe stops active session")
    finally:
        r.close()
    return results


class Upstream(http.server.BaseHTTPRequestHandler):
    hits = 0
    def do_CONNECT(self):
        # mihomo tunnels plain HTTP through an HTTP upstream too. Never contact a real destination.
        if not self.path.startswith("127.0.0.1:"):
            self.send_error(503)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.flush()
        self.connection.settimeout(2)
        first = self.rfile.readline(8192)
        assert first.startswith(b"GET ")
        total = len(first)
        while True:
            line = self.rfile.readline(8192)
            total += len(line)
            assert total <= 16384
            if line in (b"\r\n", b"\n", b""):
                break
        type(self).hits += 1
        body = b"UPSTREAM_FIXTURE"
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                         b"\r\nConnection: close\r\n\r\n" + body)
        self.close_connection = True

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"UPSTREAM_FIXTURE")

    def log_message(self, *args):
        pass


class DirectReceiver(Upstream):
    hits = 0
    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"DIRECT_FIXTURE")


@contextlib.contextmanager
def server(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def proxy_cases(binary, engine):
    profile = dict(enginePath=engine, kind="http", server="127.0.0.1", port=free_port(),
                   localPort=free_port(), username="", tls=False, serverName="", cipher="aes-128-gcm")
    r = Runtime(binary)
    try:
        r.send("startProxy", profile=profile, password="")
        event = r.event("checking")
        pid = event["proxyPID"]
        args = subprocess.check_output(["ps", "-p", str(pid), "-o", "args="], text=True)
        config_path = pathlib.Path(args.strip().split(" -f ", 1)[1])
        config = json.loads(config_path.read_text())
        assert config_path.stat().st_mode & 0o777 == 0o600
        assert config_path.parent.stat().st_mode & 0o777 == 0o700
        group = r.demo()
        os.kill(pid, signal.SIGKILL)
        r.event("fault")
        until(lambda: stopped(group))
        assert not config_path.parent.exists()
    finally:
        r.close()
    results = ["proxy crash stops task group and removes private config"]
    with server(Upstream) as upstream, server(DirectReceiver) as direct, tempfile.TemporaryDirectory() as tmp:
        config["proxies"][0]["port"] = upstream.server_port
        path = pathlib.Path(tmp) / "config.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        process = subprocess.Popen([engine, "-d", tmp, "-f", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def listening():
                try:
                    with socket.create_connection(("127.0.0.1", profile["localPort"]), timeout=0.2):
                        return True
                except OSError:
                    assert process.poll() is None, "Engine rejected generated config"
                    return False
            until(listening)
            auth = config["authentication"][0]
            target = f"http://127.0.0.1:{direct.server_port}/fixture"
            base = ["/usr/bin/curl", "--silent", "--fail", "--max-time", "3", "--noproxy", ""]
            proxied = base + ["--proxy", f"http://{auth}@127.0.0.1:{profile['localPort']}", target]
            good = subprocess.run(proxied, capture_output=True)
            assert good.returncode == 0 and good.stdout == b"UPSTREAM_FIXTURE"
            assert Upstream.hits == 1 and DirectReceiver.hits == 0
            denied = subprocess.run(base + ["--proxy", f"http://127.0.0.1:{profile['localPort']}", target], capture_output=True)
            assert denied.returncode != 0
            results.append("generated proxy routes through upstream and requires authentication")
            upstream.shutdown()
            upstream.server_close()
            bad = subprocess.run(proxied, capture_output=True)
            assert bad.returncode != 0 and DirectReceiver.hits == 0
            positive = subprocess.run(base + ["--proxy", "", target], capture_output=True)
            assert positive.returncode == 0 and positive.stdout == b"DIRECT_FIXTURE"
            results.append("dead upstream fails without DIRECT fallback; direct positive control reachable")
        finally:
            process.kill()
            process.wait(timeout=5)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime")
    parser.add_argument("--engine")
    args = parser.parse_args()
    results = runtime_cases(args.runtime)
    if args.engine:
        results += proxy_cases(args.runtime, args.engine)
    print(json.dumps({"passed": results, "proxy_fixture": "PASS" if args.engine else "NOT_RUN",
                      "claude_enforcement": "NOT_TESTED"}, indent=2))


if __name__ == "__main__":
    main()
