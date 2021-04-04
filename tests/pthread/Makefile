TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: pthread.c
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/pthread pthread.c $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

OPTS += --memory-size=512m

ifdef ALLTESTS
COUNT = 10
endif

# Increase timeout for these tests
export TIMEOUT=360

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread $(COUNT)

tests-n:
<<<<<<< HEAD
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread 1000
=======
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pthread 2
>>>>>>> disable process mappings

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs appdir
