#include "test.h"
#include <unistd.h>
#define main popen_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/popen.c"
