SUBDIR = oesdk/app
TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

SHLIB = libapp.so

INCLUDES = $(DEFAULT_INCLUDES) -I$(OE_INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(DEFAULT_CFLAGS) -fvisibility=hidden

LDFLAGS = $(DEFAULT_LDFLAGS)

LIBS = $(LIBDIR)/liboesdkhost.a

SOURCES = $(SUBOBJDIR)/app_u.c $(wildcard *.c)

CLEAN += $(SUBOBJDIR)/app_u.c

include $(TOP)/rules.mak

$(SUBOBJDIR)/app_u.c: app.edl
	$(EDGER8R) $(EDGER8R_UNTRUSTED_OPTS) app.edl

run:
	$(BINDIR)/oesdk-run $(__SHLIB)

nm:
	nm -CD $(__SHLIB)
