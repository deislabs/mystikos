TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/pthread pthread.c $(LDFLAGS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

ifdef ALLTESTS
COUNT = 10
endif

tests:
	$(RUNTEST) $(LIBOS_EXEC) $(OPTS) rootfs /bin/pthread $(COUNT)

tests-n:
	$(RUNTEST) $(LIBOS_EXEC) $(OPTS) rootfs /bin/pthread 1000

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export
