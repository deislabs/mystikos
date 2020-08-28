#include <libos/syscall.h>

long libos_syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid)
{
#ifdef ENABLE_HTHREADS
    (void)fn;
    (void)child_stack;
    (void)flags;
    (void)arg;
    (void)ptid;
    (void)newtls;
    (void)ctid;
    return 0;
#else
    (void)fn;
    (void)child_stack;
    (void)flags;
    (void)arg;
    (void)ptid;
    (void)newtls;
    (void)ctid;
    return 0;
#endif
}
