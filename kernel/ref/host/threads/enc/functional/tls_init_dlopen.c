#include "test.h"
#include <unistd.h>
#define main tls_init_dlopen_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/tls_init_dlopen.c"
