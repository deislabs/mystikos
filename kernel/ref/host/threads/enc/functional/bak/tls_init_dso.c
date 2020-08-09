#include "test.h"
#include <unistd.h>
#define main tls_init_dso_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/tls_init_dso.c"
