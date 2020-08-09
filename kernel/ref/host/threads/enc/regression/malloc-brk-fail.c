#include "test.h"
#include <unistd.h>
#define main malloc_brk_fail_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/malloc-brk-fail.c"
