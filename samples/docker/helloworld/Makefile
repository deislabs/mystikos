TOP := $(abspath ../../..)
include $(TOP)/defs.mak

APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := mystikos-hello
LDFLAGS       := -Wl,-rpath=$(MUSL_LIB)
MYST_TARBALL := mystikos.tar.gz
OPTS          := --strace
PSW_VERSION   := 2.15.100
MYST_RELEASE_VERSION := 0.5.0

.PHONY: build run tests clean

all: build 

build-local:
	cd $(TOP) && make bindist | sed -n 's/.*\(mystikos.*\.tar\.gz\).*/\1/p' | xargs -I {} mv {} $(BUILD_DIR)/$(MYST_TARBALL)

build: myst rootfs
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) --build-arg MYST_RELEASE_VERSION=$(MYST_RELEASE_VERSION) -t $(DOCKER_IMG) .

myst:
	$(MAKE) -C $(TOP)/tools/myst

rootfs: hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	@$(MYST) mkcpio $(APPDIR) rootfs

tests: build
	@docker run --rm --device=/dev/sgx:/dev/sgx $(DOCKER_IMG)

run: myst rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/hello red green blue $(OPTS)

clean:
	@rm -rf appdir $(MYST_TARBALL) rootfs
