TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = cpio_deflate

SOURCES = $(wildcard *.c)
SOURCES += ../../target/shared/sha256.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a
LDFLAGS += -lcrypto

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	rm -rf tmpdir
	$(SUBBINDIR)/$(PROGRAM) rootfs rootfs.deflated
