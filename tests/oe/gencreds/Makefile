TOP=$(abspath ../../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave

INCLUDES += $(OEENCLAVE_INCLUDES)

all: libos rootfs

rootfs: gencreds.c
	mkdir -p $(SUBBINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SUBBINDIR)/gencreds gencreds.c $(LDFLAGS)
	$(MKROOTFS) $(SUBBINDIR)/gencreds rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/gencreds $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf rootfs
