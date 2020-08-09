#include "test.h"
#include <unistd.h>
#define main pthread_atfork_errno_clobber_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/pthread_atfork-errno-clobber.c"
