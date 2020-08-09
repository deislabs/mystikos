#include <unistd.h>
#include <string.h>
#include "libc.h"
#include "pthread_impl.h"
#include "posix_signal.h"
#include "posix_spinlock.h"
#include "posix_ocall_structs.h"
#include "posix_trace.h"

#include "posix_warnings.h"

struct posix_shared_block* __posix_init_shared_block;

int __posix_init_tid;

static posix_spinlock_t _lock;

void posix_init(struct posix_shared_block* shared_block, int tid)
{
    size_t aux[64];
    static const char* _environ[] = { NULL };

    memset(aux, 0, sizeof(aux));

    __posix_init_shared_block = shared_block;
    __posix_init_tid = tid;
    __progname = "unknown";
    __sysinfo = 0;
    __environ = (char**)_environ;
    __hwcap = 0;
    __default_stacksize = 4096;

    libc.auxv = aux;
    libc.page_size = PAGESIZE;
    libc.secure = 0;

    __posix_install_exception_handler();

    /* ATTN: this does not return! */
    __init_tls(aux);
}
