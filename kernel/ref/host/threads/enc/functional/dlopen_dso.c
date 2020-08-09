#include "test.h"
#include <unistd.h>
#define main dlopen_dso_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/dlopen_dso.c"
