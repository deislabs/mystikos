#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "syscall.h"
#include "libc.h"
#include "pthread_impl.h"

static void dummy(int x)
{
}

weak_alias(dummy, __fork_handler);

pid_t fork(void)
{
	pid_t ret;
	sigset_t set;
	__fork_handler(-1);
	__block_all_sigs(&set);
#ifdef SYS_fork
	ret = __syscall(SYS_fork);
#else
	ret = __syscall(SYS_clone, SIGCHLD, 0);
#endif

        if (!ret) {
		pthread_t self = __pthread_self();
		self->tid = __syscall(SYS_gettid);
		self->robust_list.off = 0;
		self->robust_list.pending = 0;
		self->next = self->prev = self;

		// In Linux, the child process can safely modify the libc internal variables as below
		// since (v)fork creates a new memory space for the child; any changes done by the child
		// does not affect the parent.
		// However, in mystikos, after (v)fork, the child still shares the same libc/crt as the parent.
		// Therefore, it is not safe to modify the libc state. It is only after execve that the child
		// gets its own crt/libc.
		// Some LTP tests (e.g /ltp/testcases/kernel/syscalls/fchmod/fchmod05) rely on fork.
		// Those tests rely on the tid for the thread being set above.
#if 0
		__thread_list_lock = 0;
		libc.threads_minus_1 = 0;
#endif
       }

	__restore_sigs(&set);
	__fork_handler(!ret);
	return __syscall_ret(ret);
}
