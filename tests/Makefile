TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =

DIRS += fork
DIRS += vfork
DIRS += myst
DIRS += itimer
DIRS += timeval

ifdef MYST_ENABLE_EXT2FS
DIRS += ext2
DIRS += libc
endif

DIRS += args
DIRS += pthread
DIRS += urandom
DIRS += buf
DIRS += cpuid
DIRS += hello
DIRS += shlib
DIRS += getcwd
DIRS += rdtsc
DIRS += mman
DIRS += fs
DIRS += mount
DIRS += cpio
DIRS += elf
DIRS += strings
DIRS += getpid
DIRS += json
DIRS += conf
DIRS += nbio
DIRS += thread
DIRS += gdb

DIRS += dlopen
DIRS += pipe
DIRS += spawn
DIRS += spawnfa
DIRS += fstat
DIRS += popen
DIRS += system
DIRS += ids
DIRS += dup
DIRS += sockets
DIRS += sendmsg
DIRS += poll
DIRS += sysinfo
DIRS += pollpipe
DIRS += pipesz
DIRS += futex
DIRS += round
DIRS += signal
DIRS += tlscert
DIRS += tlscert2
DIRS += wake_and_kill
DIRS += cross_fs_symlinks
DIRS += arch_prctl


ifndef MYST_SKIP_LTP_TESTS
DIRS += ltp
endif

DIRS += shared_symbols

ifndef MYST_SKIP_LIBCXX_TESTS
DIRS += libcxx
ifdef MYST_NIGHTLY_TEST
DIRS += libcxx2
endif
endif

ifndef MYST_USE_OECACHE
DIRS += curl
endif

REDEFINE_TESTS=1

DIRS += epoll
DIRS += oe
DIRS += procfs

ifeq ($(MYST_ENABLE_HOSTFS),1)
DIRS += hostfs
endif

ifndef MYST_ENABLE_GCOV
ifdef MYST_NIGHTLY_TEST
DIRS += sockperf
DIRS += cpython-tests
endif
DIRS += clock
DIRS += pollpipe2
DIRS += dotnet-proc-maps
DIRS += dotnet-ubuntu
DIRS += openmp
endif

DIRS += msync

DIRS += robust
DIRS += devfs
DIRS += syscall_exception
DIRS += mutex
DIRS += mprotect
DIRS += eventfd
DIRS += polleventfd
DIRS += dotnet-sos
DIRS += tkillself
DIRS += thread_abort
DIRS += synccall
DIRS += python_subprocess
DIRS += python_vfork
DIRS += fcntl
DIRS += stacksize
DIRS += math

.PHONY: $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

tests:
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) __tests TARGET=linux TESTSUFFIX=.linux

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean: clean
