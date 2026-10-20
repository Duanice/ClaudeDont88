#!/usr/bin/env python3
"""Local TCP+UDP echo fixture for a separate, signed-filter integration experiment."""
import argparse
import socket
import threading


def serve(host, port, kind):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, kind) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        if kind == socket.SOCK_STREAM:
            server.listen(8)
            while True:
                client, _ = server.accept()
                threading.Thread(target=echo_tcp, args=(client,), daemon=True).start()
        else:
            while True:
                data, peer = server.recvfrom(4096)
                print("UDP marker received", flush=True)
                server.sendto(data, peer)


def echo_tcp(client):
    with client:
        try:
            while data := client.recv(4096):
                print("TCP marker received", flush=True)
                client.sendall(data)
        except OSError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=["127.0.0.1", "::1"], default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    threading.Thread(target=serve, args=(args.host, args.port, socket.SOCK_DGRAM), daemon=True).start()
    print("Local fixture only; receipt logs are evidence, client timeouts alone are not.", flush=True)
    serve(args.host, args.port, socket.SOCK_STREAM)
