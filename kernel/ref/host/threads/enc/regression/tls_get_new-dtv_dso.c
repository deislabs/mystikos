#include "test.h"
#include <unistd.h>
#define main tls_get_new_dtv_dso_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/tls_get_new-dtv_dso.c"
