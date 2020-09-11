TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboskernel.a

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c) $(wildcard *.s)

INCLUDES = -I$(INCDIR) $(OEENCLAVE_INCLUDES) -I$(BUILDDIR)/include

ifdef LIBOS_ENABLE_HOST_THREADS
DEFINES += -DLIBOS_ENABLE_HOST_THREADS
endif

ifdef LIBOS_USE_THREAD_STACK
DEFINES += -DLIBOS_USE_THREAD_STACK
endif

ifdef LIBOS_ENABLE_LEAK_CHECKER
DEFINES += -DLIBOS_ENABLE_LEAK_CHECKER
endif

CFLAGS = $(OEENCLAVE_CFLAGS)

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
DEFINES += -DLIBOS_ENABLE_GCOV
endif

DIRS = image

include $(TOP)/rules.mak
