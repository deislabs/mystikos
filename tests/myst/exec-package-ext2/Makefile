TOP=$(abspath ../../..)
include $(TOP)/defs.mak

TMPDIR=$(SUBOBJDIR)/tmp
APPDIR=$(TMPDIR)/appdir
ROOTFS=$(TMPDIR)/rootfs
PRIVKEY=$(TMPDIR)/private.pem
PUBKEY=$(TMPDIR)/public.pem

USER=$(shell id --user)
GROUP=$(shell id --group)

all: $(PUBKEY)
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/hello hello.c
	sudo $(MYST) mkext2 --force --sign=$(PUBKEY):$(PRIVKEY) $(APPDIR) $(ROOTFS)
	$(MYST) package --pubkey=$(PUBKEY) $(PRIVKEY) config.json

$(PUBKEY): $(PRIVKEY)
	openssl rsa -in $(PRIVKEY) -pubout -out $(PUBKEY)

$(PRIVKEY): $(TMPDIR)
	openssl genrsa -out $(PRIVKEY) -3 3072

$(TMPDIR):
	mkdir -p $(TMPDIR)

export MYST_ROOTFS_PATH=$(ROOTFS)

tests:
	$(RUNTEST) $(MYST) exec-sgx --pubkey=$(PUBKEY) $(ROOTFS) /bin/hello
	$(RUNTEST) ./myst/bin/hello

clean:
	rm -rf $(APPDIR) myst $(PRIVKEY) $(PRIVKEY) $(ROOTFS)

distclean:
	rm -rf $(SUBOBJDIR)

xxx:
	ls -l $(ROOTFS)
