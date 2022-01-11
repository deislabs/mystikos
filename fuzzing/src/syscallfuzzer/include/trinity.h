#pragma once

#include "types.h"
#include "syscallfuzzer.h"

extern syscall_fuzzer_payload* syscall_payload;
extern unsigned int num_online_cpus;
extern bool no_bind_to_cpu;

extern char *progname;

void main_loop(void);

void panic(int reason);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1

// output stuff that's used pretty much everywhere, so may as well be here.
#define MAX_LOGLEVEL 3
#define CONT -1
void output(char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void debugf(const char *fmt, ...);
