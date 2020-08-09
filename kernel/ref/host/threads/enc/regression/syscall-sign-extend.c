#include "test.h"
#include <unistd.h>
#define main syscall_sign_extend_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/syscall-sign-extend.c"
