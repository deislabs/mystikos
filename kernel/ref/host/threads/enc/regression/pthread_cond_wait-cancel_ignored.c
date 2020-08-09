#include "test.h"
#include <unistd.h>
#define main pthread_cond_wait_cancel_ignored_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/pthread_cond_wait-cancel_ignored.c"
