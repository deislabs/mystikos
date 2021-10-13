#ifndef _COMMON_H
#define _COMMON_H

#include <stddef.h>
#include <stdint.h>

void run_server(uint16_t port);

void run_client(uint16_t port);

#define BIG_FILE_SIZE (1024 * 1024) /* 1MB */

#endif /* _COMMON_H */
