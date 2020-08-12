SUBDIR = elf
TOP=$(abspath ..)
include $(TOP)/defs.mak

ARCHIVE = liboself

SOURCES = $(wildcard *.c)

INCLUDES = -I$(TOP)/include

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

include $(TOP)/rules.mak
