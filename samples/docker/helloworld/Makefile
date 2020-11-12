TOP := $(abspath ../../..)
include $(TOP)/defs.mak

APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := openlibos-hello
LDFLAGS       := -Wl,-rpath=$(MUSL_LIB)
LIBOS_TARBALL := openlibos.tar.gz
OPTS          := --strace
PSW_VERSION   := 2.11

.PHONY: build run tests clean

build: libos rootfs
	@cd $(TOP) && make bindist | sed -n 's/.*\(openlibos.*\.tar\.gz\).*/\1/p' | xargs -I {} mv {} $(BUILD_DIR)/$(LIBOS_TARBALL)
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) -t $(DOCKER_IMG) .

libos:
	$(MAKE) -C $(TOP)/tools/libos

rootfs: hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	@$(LIBOS) mkcpio $(APPDIR) rootfs

run: build
	@docker run --rm --device=/dev/sgx:/dev/sgx $(DOCKER_IMG)

tests: libos rootfs
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/hello red green blue $(OPTS)

clean:
	@rm -rf appdir $(LIBOS_TARBALL) rootfs
