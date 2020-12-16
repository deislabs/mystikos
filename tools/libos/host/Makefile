TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = libos

SOURCES =
SOURCES += $(SUBOBJDIR)/libos_u.c
SOURCES += $(wildcard *.c)
SOURCES += $(wildcard ../*.c)

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR) -I../

CFLAGS = $(OEHOST_CFLAGS)

ifdef LIBOS_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(OEHOST_LIBDIR)/liboehostmr.a
LIBS += $(OEHOST_LIBDIR)/liboesignlib.a
LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/liboshost.a
LIBS += $(LIBDIR)/libostargetcommon.a
LIBS += $(LIBDIR)/libostargetlinux.a
LIBS += $(LIBDIR)/libostargetsgxhost.a
LIBS += $(LIBDIR)/libosutils.a

CLEAN = $(SUBOBJDIR)/libos_u.h $(SUBOBJDIR)/libos_u.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_u.c: ../libos.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl

x:
	echo $(SUBOBJDIR)
