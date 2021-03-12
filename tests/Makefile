.NOTPARALLEL:

TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =

DIRS += myst
DIRS += itimer
DIRS += timeval

ifdef MYST_ENABLE_EXT2FS
DIRS += ext2
DIRS += libc
endif

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
DIRS += signal
DIRS += tlscert
DIRS += wake_and_kill
DIRS += cross_fs_symlinks

# temp 
DIRS += ltp2

ifndef MYST_SKIP_LIBCXX_TESTS
DIRS += libcxx
endif

DIRS += tlscert
DIRS += wake_and_kill

ifndef MYST_USE_OECACHE
DIRS += curl
endif

ifdef MYST_NIGHTLY_TEST
DIRS += ltp
DIRS += sockperf
endif

REDEFINE_TESTS=1
include $(TOP)/rules.mak

DIRS += epoll
DIRS += oe

ifeq ($(MYST_ENABLE_HOSTFS),1)
DIRS += hostfs
endif

DIRS += msync

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

tests:
	@ rm -rf $(TESTDIR)
	@ $(MAKE) -s __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) -s __tests TARGET=linux TESTSUFFIX=.linux
