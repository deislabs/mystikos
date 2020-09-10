#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    pid_t ppid = getppid();
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

#if 0
    printf("ppid=%d pid=%d tid=%d\n", ppid, pid, tid);
#endif

    assert(ppid != 0);
    assert(pid != 0);
    assert(tid != 0);
    assert(ppid != pid);
    assert(tid == pid);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
