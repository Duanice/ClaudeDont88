/* Raw sockets deliberately avoid Network.framework's automatic proxy selection. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void finish(const char *result, int error, int status) {
    printf("{\"result\":\"%s\",\"errno\":%d,\"api\":\"posix\"}\n", result, error);
    exit(status);
}

int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1], "exchange") && strcmp(argv[1], "connect")) ||
        (strcmp(argv[2], "tcp") && strcmp(argv[2], "udp"))) return 64;
    char *end;
    long port = strtol(argv[4], &end, 10);
    if (*end || port < 1 || port > 65535) return 64;
    int tcp = !strcmp(argv[2], "tcp");
    if (!tcp && !strcmp(argv[1], "connect")) return 64;
    struct addrinfo hints = {0}, *address = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(argv[3], argv[4], &hints, &address)) return 64;
    signal(SIGPIPE, SIG_IGN);
    alarm(8);
    int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0) finish("setup_failed", errno, 64);
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) finish("setup_failed", errno, 64);
    int result = connect(fd, address->ai_addr, address->ai_addrlen);
    freeaddrinfo(address);
    if (result < 0) {
        if (errno != EINPROGRESS) finish("connection_failed", errno, 2);
        struct pollfd pending = {.fd = fd, .events = POLLOUT};
        result = poll(&pending, 1, 2500);
        if (!result) finish("timeout", 0, 2);
        if (result < 0) finish("setup_failed", errno, 64);
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size)) finish("setup_failed", errno, 64);
        if (error) finish("connection_failed", error, 2);
    }
    if (!strcmp(argv[1], "connect")) finish("connected", 0, 0);
    struct timeval timeout = {.tv_sec = 2};
    if (fcntl(fd, F_SETFL, flags) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
        finish("setup_failed", errno, 64);
    }
    const char payload[] = "ClaudeDont88-posix-probe";
    size_t length = strlen(payload), sent = 0, received = 0;
    while (sent < length) {
        ssize_t n = send(fd, payload + sent, length - sent, 0);
        if (n <= 0) finish("send_failed", n < 0 ? errno : 0, 2);
        sent += (size_t)n;
        if (!tcp && sent != length) finish("send_failed", 0, 2);
    }
    char buffer[sizeof(payload)];
    do {
        ssize_t n = recv(fd, buffer + received, sizeof(buffer) - received, 0);
        if (n < 0) finish("receive_failed", errno, 2);
        if (!n) finish("incomplete_echo", 0, 2);
        received += (size_t)n;
    } while (tcp && received < length);
    if (received != length || memcmp(buffer, payload, length)) finish("wrong_echo", 0, 2);
    finish("echo_received", 0, 0);
}
