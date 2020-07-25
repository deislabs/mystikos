SUBDIR = samples/split
TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/run_t.c enc.c elfutils.c

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR) -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = -Werror $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -loehostfs -llthread

#LDFLAGS += -Wl,--export-dynamic
#LDFLAGS += -Wl,--hash-style=both

CLEAN = $(SUBOBJDIR)/run_t.h $(SUBOBJDIR)/run_t.c $(SUBOBJDIR)/run_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/run_t.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../run/run.edl

LIBOELCRT=$(TOP)/build/musl/lib/liboelcrt.so

tests:
	$(BINDIR)/run $(SUBBINDIR)/enc:$(LIBOELCRT)

dump:
	readelf -S $(SUBBINDIR)/enc
