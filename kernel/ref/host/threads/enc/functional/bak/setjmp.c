#include "test.h"
#include <unistd.h>
#define main setjmp_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/setjmp.c"
