TOP=$(abspath ../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = myst-sig

SOURCES += $(wildcard *.c)
SOURCES += ../../target/shared/sha256.c

INCLUDES = $(OEHOST_INCLUDES) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(MBEDTLS_LIBS)
LIBS += $(LIBDIR)/libmystutils.a

include $(TOP)/rules.mak

ALPHA=abcdefghijklmnopqrstuvwxyz
HASH=$(shell echo $(ALPHA) | sha256sum | cut -d" " -f 1)
SIGFILE=$(SUBOBJDIR)/sig

PRIVATE=$(OBJDIR)/private.pem
PUBLIC=$(OBJDIR)/public.pem
CERT=$(OBJDIR)/cert.pem

CLEAN += $(PRIVATE)
CLEAN += $(PUBLIC)
CLEAN += $(CERT)

tests: program $(PRIVATE) $(PUBLIC) $(CERT)
	$(MAKE) sign
	$(MAKE) verify
	$(MAKE) signer

sign:
	$(BINDIR)/myst-sig sign $(PRIVATE) $(HASH) > $(SIGFILE)

verify:
	$(BINDIR)/myst-sig verify $(PUBLIC) $(HASH) $(shell cat $(SIGFILE))

signer:
	$(BINDIR)/myst-sig signer $(PUBLIC)

$(PRIVATE):
	openssl genrsa -out $(PRIVATE)

$(PUBLIC): $(PRIVATE)
	openssl rsa -in $(PRIVATE) -pubout -out $(PUBLIC)

$(CERT): $(PRIVATE)
	openssl req -new -x509 -key $(PRIVATE) -out $(CERT) --config req.conf
