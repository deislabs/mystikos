SUBDIR = tools/libos/enc
TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/bin/enc
include $(TOP)/defs.mak

PROGRAM = libosenc.so

SOURCES = $(SUBOBJDIR)/libos_t.c enc.c

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(SUBOBJDIR)
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = $(OEENCLAVE_CFLAGS)

LIBS += $(LIBDIR)/liboskernel.a
LIBS += $(LIBDIR)/liblthread.a
LIBS += $(LIBDIR)/openenclave/enclave/liboehostfs.a
LIBS += $(LIBDIR)/openenclave/enclave/liboehostsock.a

LDFLAGS += $(OEENCLAVE_LDFLAGS)

CLEAN = $(SUBOBJDIR)/libos_t.h $(SUBOBJDIR)/libos_t.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_t.c: ../libos.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl
