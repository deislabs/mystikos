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
DIRS += hello
DIRS += shlib
DIRS += getcwd
DIRS += rdtsc
DIRS += run
DIRS += echo
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
DIRS += pipe
DIRS += spawn
DIRS += fstat
DIRS += popen
DIRS += system
DIRS += ids
DIRS += dup
DIRS += sockets
DIRS += sendmsg
DIRS += poll
DIRS += clock
DIRS += sysinfo
DIRS += pollpipe
DIRS += pipesz
DIRS += futex
DIRS += round

ifndef LIBOS_USE_OECACHE
DIRS += cpp-exceptions
endif

REDEFINE_TESTS=1
include $(TOP)/rules.mak

DIRS += epoll

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

tests:
	@ rm -rf $(TESTDIR)
	@ $(MAKE) -s __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) -s __tests TARGET=linux TESTSUFFIX=.linux
