TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

IMAGE=$(SUBOBJDIR)/image
ROOTHASH=$(SUBOBJDIR)/roothash
PUBKEY=$(SUBOBJDIR)/public.pem
PRIVKEY=$(SUBOBJDIR)/private.pem

all:
	$(MAKE) deps
	$(MAKE) rootfs

rootfs: main.c $(PUBKEY)
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/verity main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

deps:
	$(MAKE) -C ../../../utils
	$(MAKE) -C ../../../kernel
	$(MAKE) -C $(TOP)/tools/myst

tests: rootfs image
	$(MAKE) __tests

OPTS = --pubkey=$(PUBKEY) --roothash=$(ROOTHASH)

ifdef STRACE
OPTS += --strace
endif

__tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/verity $(IMAGE)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /bin/verity $(IMAGE)

clean:
	rm -rf $(APPDIR) rootfs export ramfs $(IMAGE) $(ROOTHASH) $(PUBKEY) $(PRIVKEY)

##==============================================================================
##
## rules to create the disk image
##
##==============================================================================

#SIZE=134217728
SIZE=1073741824

MKEXT2_OPTS += --force
MKEXT2_OPTS += --size=$(SIZE)
MKEXT2_OPTS += --sign=$(PUBKEY):$(PRIVKEY)

OUTFILE=$(SUBOBJDIR)/outfile

image: $(IMAGE)

$(IMAGE):
	mkdir -p $(SUBOBJDIR)
	$(MYST) mkext2 $(MKEXT2_OPTS) ext2dir $(IMAGE)
	$(MYST) fssig $(IMAGE) > $(OUTFILE)
	@ grep root_hash= $(OUTFILE) | cut -d= -f 2 > $(ROOTHASH)

dump:
	veritysetup dump --hash-offset=$(SIZE) $(IMAGE)

roothash:
	@cat $(ROOTHASH)

$(PRIVKEY):
	mkdir -p $(SUBOBJDIR)
	openssl genrsa -out $(PRIVKEY)

$(PUBKEY): $(PRIVKEY)
	mkdir -p $(SUBOBJDIR)
	openssl rsa -in $(PRIVKEY) -pubout -out $(PUBKEY)

cat:
	cat $(PUBKEY)

stat:
	ls -l $(PUBKEY)
