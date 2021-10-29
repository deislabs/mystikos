#define hidden __attribute__((__visibility__("hidden")))

#include <myst/syscallext.h>
#include <pthread_impl.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>

// Reimplement pthread_getattr_np() using the SYS_myst_get_process_thread_stack
// extended syscall. The musl libc version is less efficient since it uses
// mremap() probing to find the guard page. Also, the musl libc version will
// not work with Mystikos since the stack is obtained with malloc() rather
// than mmap().
int pthread_getattr_np(pthread_t thread, pthread_attr_t* attr)
{
    uintptr_t stackaddr = 0;
    size_t stacksize = 0;

    if (!thread || !attr)
        return EINVAL;

    if (thread->stack) /* this thread was created by pthread_create() */
    {
        stackaddr = (uintptr_t)thread->stack;
        stacksize = thread->stack_size;
    }
    else /* this is the main thread and was created by the program loader */
    {
        if (syscall(
                SYS_myst_get_process_thread_stack, &stackaddr, &stacksize) != 0)
            return ENOSYS;
        stackaddr += stacksize;
    }

    *attr = (pthread_attr_t){0};
    attr->_a_detach = (thread->detach_state >= DT_DETACHED) ? 1 : 0;
    attr->_a_guardsize = thread->guard_size;
    attr->_a_stackaddr = stackaddr;
    attr->_a_stacksize = stacksize;

    return 0;
}
