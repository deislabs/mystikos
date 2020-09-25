TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =
DIRS += libc
DIRS += args
DIRS += echo
DIRS += alpine
DIRS += pthread
DIRS += urandom
DIRS += buf
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
DIRS += thread
DIRS += gdb
DIRS += dlopen
DIRS += libos

DIRS = cpio

REDEFINE_TESTS=1
include $(TOP)/rules.mak

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

tests:
	@ rm -rf $(TESTDIR)
	@ $(MAKE) -s __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) -s __tests TARGET=linux TESTSUFFIX=.linux
