#ifndef _LIBOS_PROCESS_H
#define _LIBOS_PROCESS_H

#include <sys/types.h>
#include <unistd.h>

pid_t libos_getpid(void);

int libos_setpid(pid_t pid);

#endif /* _LIBOS_PROCESS_H */
