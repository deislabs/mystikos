TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = myst

SOURCES =
SOURCES += $(SUBOBJDIR)/myst_u.c
SOURCES += $(wildcard *.c)
SOURCES += $(wildcard ../*.c)

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR) -I../

CFLAGS = $(OEHOST_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(OEHOST_LIBDIR)/liboehostmr.a
LIBS += $(OEHOST_LIBDIR)/liboesignlib.a
LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmysthost.a
LIBS += $(LIBDIR)/libmysttargetcommon.a
LIBS += $(LIBDIR)/libmysttargetlinux.a
LIBS += $(LIBDIR)/libmysttargetsgxhost.a
LIBS += $(LIBDIR)/libmystutils.a

CLEAN = $(SUBOBJDIR)/myst_u.h $(SUBOBJDIR)/myst_u.c $(SUBOBJDIR)/myst_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/myst_u.c: ../myst.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../myst.edl

x:
	echo $(SUBOBJDIR)
