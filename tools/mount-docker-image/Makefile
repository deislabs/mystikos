TOP=$(abspath ../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = mount-docker-image

SOURCES += $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_ENABLE_GCOV
LIBS += $(LIBDIR)/libmystgcovserver.a
endif

LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

all:
	$(MAKE) empty_directory
	make program

# create the empty directory needed by single-level overlayfs mounts
empty_directory:
	mkdir -p $(BUILDDIR)/var/empty

include $(TOP)/rules.mak
