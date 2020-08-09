#include "test.h"
#include <unistd.h>
#define main sigprocmask_internal_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/sigprocmask-internal.c"
