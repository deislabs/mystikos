SUBDIR = oesdk/app
TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBBINDIR = $(BINDIR)

CC = $(MUSL_GCC)

PROGRAM = oesdk-run

INCLUDES = $(DEFAULT_INCLUDES)

CFLAGS = $(DEFAULT_CFLAGS)

LDFLAGS = $(DEFAULT_LDFLAGS)

SOURCES = $(wildcard *.c)

include $(TOP)/rules.mak
