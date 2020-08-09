#include "test.h"
#include <unistd.h>
#define main lseek_large_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/lseek-large.c"
