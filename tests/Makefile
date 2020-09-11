TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =
DIRS += urandom
DIRS += buf
DIRS += paths
DIRS += cpuid
DIRS += argv
DIRS += shlib
DIRS += getcwd
DIRS += rdtsc
DIRS += run
DIRS += echo
DIRS += lthread
DIRS += wake
DIRS += mman
DIRS += fs
DIRS += mount
DIRS += cpio
DIRS += elf
DIRS += strings
DIRS += empty
DIRS += getpid
DIRS += json
DIRS += conf
DIRS += nbio
DIRS += libc

# This tests fails with gcov enabled
ifndef LIBOS_ENABLE_GCOV
DIRS += thread
endif

include $(TOP)/rules.mak
