#include "test.h"
#include <unistd.h>
#define main pthread_robust_detach_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/pthread-robust-detach.c"
