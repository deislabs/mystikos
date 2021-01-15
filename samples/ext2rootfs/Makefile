TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: appdir keyfile private.pem public.pem rootfs

appdir:
	mkdir -p appdir/bin
	$(MUSL_GCC) -o appdir/bin/hello hello.c

MKEXT2_OPTS += --force
#MKEXT2_OPTS += --encrypt=keyfile
MKEXT2_OPTS += --sign=public.pem:private.pem

rootfs:
	myst mkext2 $(MKEXT2_OPTS) appdir rootfs

keyfile:
	head -c 64 /dev/urandom > keyfile

private.pem:
	openssl genrsa -out private.pem

public.pem: private.pem
	openssl rsa -in private.pem -pubout -out public.pem

dump:
	myst fssig rootfs

run: deps
	myst exec-sgx --pubkey=public.pem rootfs /bin/hello

run2: deps
	myst mkcpio appdir rootfs2
	myst exec-sgx rootfs2 /bin/hello


gdb: deps
	myst-gdb --args myst exec-sgx --pubkey=public.pem rootfs /bin/hello

clean:
	rm -rf rootfs private.pem public.pem keyfile appdir

deps:
	$(MAKE) -C ../../crt
	$(MAKE) -C ../../kernel
