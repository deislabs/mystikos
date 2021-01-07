TOP := $(abspath ../../..)
include $(TOP)/defs.mak

APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := Mystikos-hello
LDFLAGS       := -Wl,-rpath=$(MUSL_LIB)
MYST_TARBALL := Mystikos.tar.gz
OPTS          := --strace
PSW_VERSION   := 2.11

.PHONY: build run tests clean

build: myst rootfs
	@cd $(TOP) && make bindist | sed -n 's/.*\(Mystikos.*\.tar\.gz\).*/\1/p' | xargs -I {} mv {} $(BUILD_DIR)/$(MYST_TARBALL)
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) -t $(DOCKER_IMG) .

myst:
	$(MAKE) -C $(TOP)/tools/myst

rootfs: hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	@$(MYST) mkcpio $(APPDIR) rootfs

run: build
	@docker run --rm --device=/dev/sgx:/dev/sgx $(DOCKER_IMG)

tests: myst rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/hello red green blue $(OPTS)

clean:
	@rm -rf appdir $(MYST_TARBALL) rootfs
