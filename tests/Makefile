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
DIRS += hello_world
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
DIRS += lldb

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
DIRS += sys_execve
DIRS += pollpipe
DIRS += pipesz
DIRS += futex
DIRS += round
DIRS += signal

ifneq ($(TARGET),linux)
DIRS += tlscert
DIRS += tlscert2
endif

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
endif
DIRS += clock
DIRS += pollpipe2
DIRS += dotnet-lib-5
DIRS += dotnet-lib-6
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
DIRS += unhandled_syscall_enosys
DIRS += stack_overflow
DIRS += sendfile
DIRS += strtonum
DIRS += fsflags
DIRS += hostfs_uds

ifdef MYST_NIGHTLY_TEST
DIRS += aspnetcore5
DIRS += aspnetcore6
DIRS += glibc
endif

DIRS += appenv

.PHONY: $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

ifdef MYST_DO_CLEANUP
remove_appdir = rm -rf $(1)/appdir
else
remove_appdir =
endif

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests; $(call remove_appdir,$(i)) $(NL) )

tests:
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) __tests TARGET=linux TESTSUFFIX=.linux

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean: clean

pipe-tests:
	$(MAKE) -C pipe tests
	$(MAKE) -C pollpipe tests
	$(MAKE) -C pollpipe2 tests
	$(MAKE) -C spawn tests
	$(MAKE) -C spawnfa tests
	$(MAKE) -C ltp pipe-tests

pipe-build:
	$(MAKE) -C pipe
	$(MAKE) -C pollpipe
	$(MAKE) -C pollpipe2
	$(MAKE) -C spawn
	$(MAKE) -C spawnfa
	$(MAKE) -C ltp
