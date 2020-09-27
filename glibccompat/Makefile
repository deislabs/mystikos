TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libosglibccompat.a

SOURCES = $(wildcard *.c)

INCLUDES = $(DEFAULT_INCLUDES)

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
CFLAGS += -Os
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections

LDFLAGS = $(DEFAULT_LDFLAGS)

include $(TOP)/rules.mak
