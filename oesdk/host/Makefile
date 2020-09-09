SUBDIR = oesdk/host
TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

SUBLIBDIR = $(LIBDIR)

ARCHIVE = liboesdkhost.a

INCLUDES = $(DEFAULT_INCLUDES) -I$(OE_INCDIR)

CFLAGS = $(DEFAULT_CFLAGS) -fvisibility=hidden

LDFLAGS = $(DEFAULT_LDFLAGS)

SOURCES = $(wildcard *.c)

include $(TOP)/rules.mak
