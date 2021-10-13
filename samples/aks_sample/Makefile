TOP := $(abspath ../..)
include $(TOP)/defs.mak

APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := mystikos-hello
LDFLAGS := -Wl,-rpath=$(MUSL_LIB)
MYST_TARBALL := mystikos.tar.gz
OPTS          := --strace
PSW_VERSION   := 2.15.100
MYST_RELEASE_VERSION := 0.5.0

.PHONY: build run tests clean

all: clean build 

build: myst $(APPDIR) container

$(APPDIR): hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@gcc $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)

container:
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) --build-arg MYST_RELEASE_VERSION=$(MYST_RELEASE_VERSION) -t $(DOCKER_IMG) .

myst:
	$(MAKE) -C $(TOP)/tools/myst

package:
	$(MYST) package-sgx $(APPDIR) private.pem config.json

private.pem:
	openssl genrsa -out private.pem -3 3072

run: build
	@docker run --rm --device=/dev/sgx:/dev/sgx $(DOCKER_IMG)

native:
	./myst/bin/hello red green blue

clean:
	@rm -rf $(APPDIR) $(MYST_TARBALL) private.pem myst 
