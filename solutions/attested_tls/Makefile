.PHONY: all app cpio oe_enclave

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

export PATH := $(PATH):$(BUILDDIR)/openenclave/bin
export PKG_CONFIG_PATH:=$(BUILDDIR)/openenclave/share/pkgconfig

DNSSERVER = $(shell systemd-resolve --status | grep "DNS Servers" | cut -f2 -d:)

all: libos app
	$(LIBOS) mkcpio $(APPDIR) rootfs

#OPTS = --trace-syscalls

run: app cpio oe_enclave 
	# Kill the running instance of the TLS server before exit.
	@trap "exit" INT TERM
	@trap "killall -9 tlssrv_host" EXIT
	# Launch the TLS server the OE enclave
	@oe_enclave/host/tlssrv_host oe_enclave/enc/tlssrv_enc.signed hw &
	@echo "OE Enclave app started..."
	# Launch the TLS client with libos
	$(LIBOS_EXEC) rootfs /client 127.0.0.1 $(OPTS)
	@wait

run-host: oe_enclave
	# Kill the running instance of the TLS server before exit.
	@trap "exit" INT TERM
	@trap "killall -9 tlssrv_host" EXIT
	# Launch the TLS server the OE enclave
	@oe_enclave/host/tlssrv_host oe_enclave/enc/tlssrv_enc.signed hw &
	@echo "OE Enclave app started..."
	# Give server some time to start up.
	sleep 1
	cp $(TOP)/include/libos/tee.h app
	gcc -g -o app/client app/client.c app/tlscli.c -lmbedtls -lmbedx509 -lmbedcrypto
	# We rely on private_key.pem and cert.der in "app" folder for attested TLS.
	app/client 127.0.0.1
	@wait

libos:
	$(MAKE) -C $(TOP)/tools/libos

app:
	rm -rf app/client app/tee.h
	docker build -t alpine.build -f app-dockerfile .
	cp $(TOP)/include/libos/tee.h app
	docker run --rm -v $(CURDIR)/app:/app alpine.build bash -c \
    "gcc -g -o /app/client /app/client.c /app/tlscli.c -lmbedtls -lmbedx509 -lmbedcrypto"
	sudo chown $(USER):$(GROUP) app/client
	$(TOP)/scripts/appbuilder Dockerfile
	cp app/client $(APPDIR)/
	# We need the manifesto file inform the app we are running in enclave.
	touch $(APPDIR)/manifesto
	# make sure the app we are running is the one we just built.
	ls -l $(APPDIR)/client; date

oe_enclave:
	make -C oe_enclave/enc
	make -C oe_enclave/host

cpio: app
	$(LIBOS) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs appdir
	make clean -C oe_enclave/enc
	make clean -C oe_enclave/host
	rm -rf app/client app/tee.h
