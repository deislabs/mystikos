SUBDIR = samples/split
TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/run_t.c $(wildcard *.c)

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(SUBOBJDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = -Werror $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -loehostfs -loel -llthread

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

tests: main
	$(BINDIR)/run $(SUBBINDIR)/enc:$(LIBOELCRT)

gdb:
	echo $(SUBBINDIR)/enc:$(LIBOELCRT)
	$(BINDIR)/oegdb -x gdb.conf --args $(BINDIR)/run $(SUBBINDIR)/enc:$(LIBOELCRT)

MUSL_GCC=$(TOP)/build/musl/bin/musl-gcc
MUSL_LIB=$(TOP)/build/musl/lib

main:
	mkdir -p $(SUBBINDIR)
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(SUBBINDIR)/main main.c
