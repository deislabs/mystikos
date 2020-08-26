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

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR) -I$(TOP)/include

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(BINDIR)/liboehostmr.a
LIBS = $(LIBDIR)/liboesignlib.a
LIBS += $(LIBDIR)/liboshost.a

CLEAN = $(SUBOBJDIR)/libos_u.h $(SUBOBJDIR)/libos_u.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_u.c: ../libos.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl
