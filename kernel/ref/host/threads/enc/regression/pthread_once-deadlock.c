#include "test.h"
#include <unistd.h>
#define main pthread_once_deadlock_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/pthread_once-deadlock.c"
