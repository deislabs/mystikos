#include "test.h"
#include <unistd.h>
#define main pthread_rwlock_ebusy_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/pthread_rwlock-ebusy.c"
