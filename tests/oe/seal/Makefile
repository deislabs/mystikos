TOP=$(abspath ../../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave -lmbedcrypto

INCLUDES += $(OEENCLAVE_INCLUDES)

all: libos rootfs

rootfs: seal.c
	mkdir -p $(SUBBINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SUBBINDIR)/seal seal.c $(LDFLAGS)
	$(MKROOTFS) $(SUBBINDIR)/seal rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/seal $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf rootfs
