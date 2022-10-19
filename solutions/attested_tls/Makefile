.PHONY: all app cpio oe_enclave

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

OEENCLAVE = oe_enclave/enc/tlssrv_enc.signed
OEDUMP = $(BUILDDIR)/openenclave/bin/oesign dump -e $(OEENCLAVE)
PATH := $(PATH):$(BUILDDIR)/openenclave/bin
export PKG_CONFIG_PATH := $(BUILDDIR)/openenclave/share/pkgconfig
export AZDCAP_DEBUG_LOG_LEVEL := 0

all: myst app
	$(MYST) mkcpio $(APPDIR) rootfs

#OPTS = --strace

_run: appdir
	# Kill the running instance of the TLS server before exit.
	@trap "exit" INT TERM
	@trap "killall -9 tlssrv_host" EXIT
	# Launch the TLS server the OE enclave
	@oe_enclave/host/tlssrv_host oe_enclave/enc/tlssrv_enc.signed hw &
	@echo "OE Enclave app started..."
	# Launch the TLS client with myst
	$(MYST_EXEC) rootfs /client 127.0.0.1 $(OPTS)
	@wait
	
run:
	$(RUNTEST) make -C $(CURDIR) _run

myst:
	$(MAKE) -C $(TOP)/tools/myst

app:	app/peer_tee_identity.h
	rm -rf app/client app/tee.h
	docker build -t attested_tls.alpine.build -f app-dockerfile .
	cp $(TOP)/include/myst/tee.h app
	$(MYST_RETRY) docker run --rm -v $(CURDIR)/app:/app attested_tls.alpine.build bash -c \
    "gcc -g -o /app/client /app/client.c /app/tlscli.c -lmbedtls -lmbedx509 -lmbedcrypto $(MYST_DEFINES)"
	sudo chown $(USER):$(GROUP) app/client
	$(TOP)/scripts/appbuilder Dockerfile
	cp app/client $(APPDIR)/
	# make sure the app we are running is the one we just built.
	ls -l $(APPDIR)/client; date

oe_enclave:
	make -C oe_enclave/enc
	make -C oe_enclave/host

app/peer_tee_identity.h: oe_enclave
	# Generate peer identity file for the other enclave
	echo "#ifndef _PEER_TEE_IDENTITY_H" > app/peer_tee_identity.h
	echo "#define _PEER_TEE_IDENTITY_H\n" >> app/peer_tee_identity.h
	echo "#define PEER_PRODUCT_ID $(shell $(OEDUMP) | grep product_id= | cut -d= -f2)" >> app/peer_tee_identity.h
	echo "#define PEER_SVN $(shell $(OEDUMP) | grep security_version= | cut -d= -f2)" >> app/peer_tee_identity.h
	echo "#define PEER_DEBUG $(shell $(OEDUMP) | grep debug= | cut -d= -f2)" >> app/peer_tee_identity.h
	echo "#define PEER_MRENCLAVE \"$(shell $(OEDUMP) | grep mrenclave= | cut -d= -f2)\"" >> app/peer_tee_identity.h
	echo "#define PEER_MRSIGNER \"$(shell $(OEDUMP) | grep mrsigner= | cut -d= -f2)\"" >> app/peer_tee_identity.h
	echo "\n#endif" >> app/peer_tee_identity.h

cpio: app
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs appdir
	make clean -C oe_enclave/enc
	make clean -C oe_enclave/host
	rm -rf app/client app/tee.h app/peer_tee_identity.h
	docker rmi attested_tls.alpine.build || true

