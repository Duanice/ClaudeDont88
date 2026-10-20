#!/usr/bin/env python3
"""Test the real probe against local echo servers. This does NOT test a loaded filter."""
import argparse
import json
import pathlib
import socket
import subprocess
import threading


def check(probe, protocol, host):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as server:
        server.bind((host, 0))
        server.settimeout(10)
        port = server.getsockname()[1]
        if protocol == "tcp":
            server.listen(1)
        errors = []

        def echo():
            try:
                if protocol == "tcp":
                    client, _ = server.accept()
                    with client:
                        client.settimeout(5)
                        while data := client.recv(4096):
                            client.sendall(data)
                else:
                    data, peer = server.recvfrom(4096)
                    server.sendto(data, peer)
            except Exception as exc:
                errors.append(str(exc))

        worker = threading.Thread(target=echo)
        worker.start()
        result = subprocess.run([str(probe), "exchange", protocol, host, str(port)],
                                text=True, capture_output=True, timeout=12)
        worker.join(timeout=11)
        assert not worker.is_alive(), "Echo server did not stop"
        assert not errors, errors
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["result"] == "echo_received"
        return {"transport": protocol, "address_family": family.name, "result": "baseline_echo_pass"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", type=pathlib.Path)
    args = parser.parse_args()
    probe = args.probe.resolve()
    results = [check(probe, protocol, host)
               for protocol in ["tcp", "udp"] for host in ["127.0.0.1", "::1"]]
    invalid = subprocess.run([str(probe), "exchange", "tcp", "example.com", "443"],
                             capture_output=True, timeout=5)
    assert invalid.returncode == 64, "Probe must reject hostnames to avoid accidental DNS"
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        # A bound, non-listening TCP socket makes this a deterministic refusal fixture.
        refusal = subprocess.run([str(probe), "exchange", "tcp", "127.0.0.1", str(port)],
                                 text=True, capture_output=True, timeout=12)
        assert refusal.returncode == 2, refusal.stdout
    print(json.dumps({"suite": "probe_baseline", "filter_enforcement": "NOT_TESTED",
                      "cases": results, "hostname_rejected": True, "closed_port_failed": True}, indent=2))


if __name__ == "__main__":
    main()
