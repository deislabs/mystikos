#include "test.h"
#include <unistd.h>
#define main mkstemp_failure_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/mkstemp-failure.c"
