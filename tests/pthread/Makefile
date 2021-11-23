TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC -I$(TOP)/include
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: pthread.c exit_status.c
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/pthread_musl pthread.c $(LDFLAGS)
	$(CC) $(CFLAGS) -DATTR_AFFINITY_NP -o appdir/bin/pthread_gcc pthread.c -lpthread $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/exit_status exit_status.c -lpthread $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=512m

# Increase timeout for these tests
export TIMEOUT=360

MAX_CPUS=--max-cpus=1024
NPROCS=$(shell nproc)

tests:
	$(MAKE) test_musl
	$(MAKE) test_gcc
	$(MAKE) test_exit_on_thread

test_musl: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_musl $(NPROCS) $(COUNT) 

test_gcc: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_gcc $(NPROCS) $(COUNT)

test_exit_on_thread: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/exit_status tests

t:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(MAX_CPUS) rootfs /bin/pthread_gcc $(NPROCS) $(COUNT)

tn:
	$(foreach i, $(shell seq 1 10), \
            $(RUNTEST) $(MYST_EXEC) $(OPTS) $(MAX_CPUS) rootfs /bin/pthread_gcc $(NRPOC) $(COUNT)\
            $(NL))

tests-n:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_musl $(NPROCS) 1000
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_gcc $(NPROCS) 1000

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs appdir
