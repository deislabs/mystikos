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
    pid_t pid = 0;
    char* const child_argv[] = {"/bin/child", "arg1", "arg2", NULL};
    char* const child_envp[] = {"X=1", "Y=1", NULL};
    int wstatus;

    r = posix_spawn(&pid, "/bin/child", NULL, NULL, child_argv, child_envp);

    if (r != 0)
    {
        printf("r=%d\n", r);
        assert(0);
    }

    assert(waitpid(pid, &wstatus, WNOHANG) == 0);
    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 123);

    printf("parent: pid %d\n", pid);
    printf("parent: exit status: %d\n", WEXITSTATUS(wstatus));

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
