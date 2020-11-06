#include <assert.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    int r;
    pid_t spid = 0;
    pid_t cpid = 0;
    char* const sargv[] = {"/ssl_server", NULL};
    char* const cargv[] = {"/ssl_client1", NULL};
    int wstatus;

    if (posix_spawn(&spid, "/ssl_server", NULL, NULL, sargv, NULL) != 0)
        assert(0);

    fprintf(stderr, "********** Created server...\n");

    sleep(1);

    if (posix_spawn(&cpid, "/ssl_client1", NULL, NULL, cargv, NULL) != 0)
        assert(0);

    fprintf(stderr, "********** Created client...\n");

    /* wait for client to exit */
    assert(waitpid(cpid, &wstatus, WNOHANG) == 0);
    assert(waitpid(cpid, &wstatus, 0) == cpid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 0);

    sleep(10);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
