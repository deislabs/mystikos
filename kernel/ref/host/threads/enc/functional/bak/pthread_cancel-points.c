#include "test.h"
#include <unistd.h>
#define main pthread_cancel_points_main
#include "../../../../../3rdparty/libc/libc-test/src/functional/pthread_cancel-points.c"
