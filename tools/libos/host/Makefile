SUBDIR = tools/libos/host
TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = libos

SOURCES = $(SUBOBJDIR)/libos_u.c
SOURCES += $(wildcard *.c)
SOURCES += $(wildcard $(TOP)/shared/*.c)
SOURCES += $(TOP)/compat/file.c
SOURCES += $(TOP)/compat/dirent.c

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS =
LIBS += $(OEHOST_LIBDIR)/liboehostmr.a
LIBS += $(OEHOST_LIBDIR)/liboesignlib.a
LIBS += $(LIBDIR)/liboshost.a

CLEAN = $(SUBOBJDIR)/libos_u.h $(SUBOBJDIR)/libos_u.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_u.c: ../libos.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl
