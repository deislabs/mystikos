#ifndef _LIBOS_PROCESS_H
#define _LIBOS_PROCESS_H

#include <sys/types.h>
#include <unistd.h>

pid_t libos_getpid(void);

int libos_setpid(pid_t pid);

pid_t libos_getppid(void);

int libos_setppid(pid_t ppid);

#endif /* _LIBOS_PROCESS_H */
