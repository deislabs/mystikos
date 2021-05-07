TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC -I$(TOP)/include
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: pthread.c
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/pthread_musl pthread.c $(LDFLAGS)
	$(CC) $(CFLAGS) -DATTR_AFFINITY_NP -o appdir/bin/pthread_gcc pthread.c -lpthread $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=512m

ifdef ALLTESTS
COUNT = 10
endif

# Increase timeout for these tests
export TIMEOUT=360

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_musl $(COUNT)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_gcc $(COUNT)

tests-n:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_musl 1000
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread_gcc 1000

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs appdir
