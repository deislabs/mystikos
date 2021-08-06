TOP=$(abspath ../../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave -L$(BUILDDIR)/mbedtls/lib -lmbedcrypto

INCLUDES += $(OEENCLAVE_INCLUDES)

ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
DEFINES += -DMYST_ENABLE_ZERO_BASE_ENCLAVES
endif

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: zerobase.c
	mkdir -p $(SUBBINDIR)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $(SUBBINDIR)/zerobase zerobase.c $(LDFLAGS)
	$(MKROOTFS) $(SUBBINDIR)/zerobase rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/zerobase $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs
