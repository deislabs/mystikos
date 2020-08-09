#include "test.h"
#include <unistd.h>
#define main getpwnam_r_errno_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/getpwnam_r-errno.c"
