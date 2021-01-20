TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

IMAGE=$(SUBOBJDIR)/image
KEYFILE=$(SUBOBJDIR)/keyfile
KEY := $(shell cat $(KEYFILE) | hexdump -v -e '/1 "%02x"' 2> /dev/null)
ROOTHASH=$(SUBOBJDIR)/roothash

all: deps rootfs

rootfs: main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/luks main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests: rootfs $(KEYFILE) $(IMAGE)
	$(MAKE) __tests

OPTS = --roothash=$(ROOTHASH)

ifdef STRACE
OPTS = --strace
endif


__tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/luks $(IMAGE) $(KEY)

clean:
	rm -rf $(APPDIR) rootfs export ramfs $(IMAGE) $(ROOTHASH) $(KEYFILE)

deps:
	$(MAKE) -C $(TOP)/tools/myst

##==============================================================================
##
## rules to create the disk image
##
##==============================================================================

KEYSIZE=64

image: $(IMAGE)

MKEXT2_OPTS =
MKEXT2_OPTS += --force
MKEXT2_OPTS += --encrypt=$(KEYFILE)
MKEXT2_OPTS += -p=passphrase12345

OUTFILE=$(SUBOBJDIR)/outfile

$(IMAGE):
	mkdir -p $(SUBOBJDIR)
	$(MYST) mkext2 $(MKEXT2_OPTS) ext2dir $(IMAGE)
	$(MYST) fssig $(IMAGE) > $(OUTFILE)
	@ grep root_hash= $(OUTFILE) | cut -d= -f 2 > $(ROOTHASH)

$(KEYFILE):
	mkdir -p $(SUBOBJDIR)
	head -c $(KEYSIZE) /dev/urandom > $(KEYFILE)
