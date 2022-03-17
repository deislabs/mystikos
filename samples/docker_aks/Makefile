APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := mystikos-hello
MYST_TARBALL := mystikos.tar.gz
PSW_VERSION   := 2.15.100
MYST_RELEASE_VERSION := 0.5.0

.PHONY: build run tests clean

all: clean build

build: $(APPDIR) 

$(APPDIR): hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@gcc $(CFLAGS) -o $(APPDIR)/bin/hello hello.c
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) --build-arg MYST_RELEASE_VERSION=$(MYST_RELEASE_VERSION) -t $(DOCKER_IMG) .

run: build
	@docker run --rm --device=/dev/sgx:/dev/sgx $(DOCKER_IMG)

clean:
	@rm -rf $(APPDIR) $(MYST_TARBALL) private.pem 
