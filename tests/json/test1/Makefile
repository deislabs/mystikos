TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = jsontest1

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(LIBDIR)/liboshost.a
LIBS += $(LIBDIR)/libjson.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(SUBBINDIR)/jsontest1 sample.json
