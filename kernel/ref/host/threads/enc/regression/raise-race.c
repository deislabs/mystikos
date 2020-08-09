#include "test.h"
#include <unistd.h>
#define main raise_race_main
#include "../../../../../3rdparty/libc/libc-test/src/regression/raise-race.c"
