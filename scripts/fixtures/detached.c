#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// No networking. The detached child has a bounded lifetime even if a test fails.
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (!strcmp(argv[1], "fast")) {
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(1);
            if (grandchild > 0) _exit(0);
        } else {
            usleep(400000); // Permit observation before leaving the original process group.
        }
        if (setsid() < 0) _exit(1);
        printf("%d\n", getpid());
        fflush(stdout);
        sleep(10);
        _exit(0);
    }
    sleep(8);
    return 0;
}
