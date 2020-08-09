#include "test.h"
#include <unistd.h>
#define main vfork_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/vfork.c"
