#!/usr/bin/env python3
"""Check a narrow loopback rule with receiver evidence. Never launches Claude."""
import argparse
import json
import pathlib
import socket
import subprocess
import threading


def rules(probe, port):
    assert probe.is_absolute() and probe.is_file()
    assert 1024 <= port <= 65535
    common = dict(process=str(probe), direction="outgoing", priority="high")
    return {
        "name": "ClaudeDont88 feasibility probe ONLY",
        "description": "Local experiment, not Claude protection. Remove these two rules to roll back.",
        "rules": [
            dict(common, action="deny", remote="any", notes="Deny only the dedicated probe."),
            dict(common, action="allow", **{"remote-addresses": "127.0.0.1"},
                 ports=str(port), protocol="tcp", notes="The only allowed loopback endpoint."),
        ],
    }


def exercise(probe, protocol, host, port, should_allow):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    stop = threading.Event()
    received = []
    errors = []
    control = b"ClaudeDont88-positive-control"
    with socket.socket(family, kind) as server:
        if protocol == "tcp":
            # Consecutive experiments reuse the allowed port while old sockets finish TIME_WAIT.
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.settimeout(0.2)
        port = server.getsockname()[1]
        if protocol == "tcp":
            server.listen(5)

        def echo():
            while not stop.is_set():
                try:
                    if protocol == "tcp":
                        client, _ = server.accept()
                        with client:
                            client.settimeout(1)
                            try:
                                data = client.recv(4096)
                            except socket.timeout:
                                data = b""
                            if data != control:
                                received.append({"connection": True, "bytes": len(data)})
                            if data:
                                client.sendall(data)
                    else:
                        data, peer = server.recvfrom(4096)
                        if data != control:
                            received.append({"datagram": True, "bytes": len(data)})
                        server.sendto(data, peer)
                except socket.timeout:
                    continue
                except OSError as error:
                    errors.append(type(error).__name__)

        def positive():
            with socket.socket(family, kind) as client:
                client.settimeout(2)
                client.connect((host, port))
                client.sendall(control)
                assert client.recv(4096) == control, "Unfiltered positive control failed"

        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        try:
            positive()
            result = subprocess.run([str(probe), "exchange", protocol, host, str(port)],
                                    capture_output=True, text=True, timeout=10)
            positive()
        finally:
            stop.set()
            thread.join(timeout=2)
        assert not thread.is_alive() and not errors, errors
    try:
        detail = json.loads(result.stdout)
    except ValueError:
        detail = {"result": "invalid_probe_response"}
    assert result.returncode in (0, 2), "Probe did not complete normally"
    assert detail.get("result") in {"echo_received", "connection_failed", "send_failed",
                                    "receive_failed", "timeout", "incomplete_echo", "wrong_echo"}
    passed = (result.returncode == 0 and detail["result"] == "echo_received" and bool(received)) if should_allow else (
        result.returncode == 2 and not received
    )
    return dict(protocol=protocol, address=host, port=port,
                expected="allow" if should_allow else "deny", passed=passed,
                receiver_observations=received, positive_controls="passed", probe=detail)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", type=pathlib.Path)
    parser.add_argument("--allowed-port", type=int, default=17988)
    parser.add_argument("--write-rules", type=pathlib.Path,
                        help="Write a reviewable rule file and exit; never imports or enables rules")
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--baseline", action="store_true",
                        help="Expect every local receiver to be reachable before installing rules")
    args = parser.parse_args()
    probe = args.probe.resolve(strict=True)
    if args.write_rules:
        args.write_rules.write_text(json.dumps(rules(probe, args.allowed_port), indent=2) + "\n")
        return
    if not args.baseline:
        state = subprocess.check_output(["systemextensionsctl", "list"], text=True)
        active = any(line.split()[:4] == ["*", "*", "MLZF7K7B5R", "at.obdev.littlesnitch.networkextension"]
                     and "[activated enabled]" in line for line in state.splitlines())
        assert active, "Little Snitch extension is not registered as active"
    cases = [exercise(probe, "tcp", "127.0.0.1", args.allowed_port, True)]
    cases += [exercise(probe, protocol, host, 0, args.baseline)
              for protocol, host in [("tcp", "127.0.0.1"), ("udp", "127.0.0.1"),
                                     ("tcp", "::1"), ("udp", "::1")]]
    if args.baseline:
        negative = exercise(probe, "tcp", "127.0.0.1", 0, False)
        assert not negative["passed"], "An unrestricted baseline was falsely reported blocked"
    passed = all(case["passed"] for case in cases)
    report = dict(scope="loopback endpoints only; no real Claude or Internet enforcement tested",
                  mode="baseline" if args.baseline else "restricted", passed=passed, cases=cases,
                  full_protection="NOT_VERIFIED")
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
