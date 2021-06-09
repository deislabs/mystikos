TOP=$(abspath ../../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave -L$(BUILDDIR)/mbedtls/lib -lmbedcrypto

INCLUDES += $(OEENCLAVE_INCLUDES)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: seal.c
	mkdir -p $(SUBBINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SUBBINDIR)/seal seal.c $(LDFLAGS)
	$(MKROOTFS) $(SUBBINDIR)/seal rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/seal $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs
