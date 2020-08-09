#include "test.h"
#include <unistd.h>
#define main putenv_doublefree_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/putenv-doublefree.c"
