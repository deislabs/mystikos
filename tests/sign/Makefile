TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: hello.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(MYST) mkext2 $(APPDIR) rootfs

OPTS =

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

OPTS += --thread-stack-size=1048576

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/hello $(OPTS)
	$(MAKE) sign
	$(MAKE) verify
	$(MAKE) fail
	@ echo "=== passed all tests"

private.pem:
	openssl genrsa -out private.pem -3 3072

sign: private.pem
	$(MYST) fssig --roothash rootfs > roothash
	rm -rf hello.signed
	$(MYST) sign-sgx rootfs private.pem config.json --roothash=roothash

verify:
	( cd hello.signed; ./bin/myst exec-sgx rootfs /bin/hello $(OPTS) )

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs hello.signed roothash private.pem

##
## Negative test to verify that hacking rootfs fails loading.
##
fail:
	$(MAKE) sign
	$(MYST) mkext2 --force $(APPDIR) hello.signed/rootfs
	$(MAKE) verify 2> /dev/null; test $$? -eq 2
