TOP=$(abspath ../../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave

INCLUDES += $(OEENCLAVE_INCLUDES)

all: myst rootfs

rootfs: gencreds.c
	mkdir -p $(SUBBINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SUBBINDIR)/gencreds gencreds.c $(LDFLAGS)
	$(MKROOTFS) $(SUBBINDIR)/gencreds rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/gencreds $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs
