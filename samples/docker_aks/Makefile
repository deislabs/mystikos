TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPDIR        := appdir
BUILD_DIR     := $(CURDIR)
CFLAGS        := -fPIC
DOCKER_IMG    := mystikos-hello
MYST_TARBALL := mystikos.tar.gz
PSW_VERSION   := 2.15.100
MYST_RELEASE_VERSION := 0.5.0
PACKAGE := myst/bin/hello

.PHONY: $(APPDIR) run clean

all: clean $(APPDIR)

$(APPDIR): hello.c
	@rm -rf $(APPDIR)
	@mkdir -p $(APPDIR)/bin
	@gcc $(CFLAGS) -o $(APPDIR)/bin/hello hello.c
	@docker build --build-arg PSW_VERSION=$(PSW_VERSION) --build-arg MYST_RELEASE_VERSION=$(MYST_RELEASE_VERSION) -t $(DOCKER_IMG) .

# IMPORTANT: 
# Before running this option, please set the RESOURCE_GROUP and CLUSTER_NAME options
# in the helloworld_aks_demo.sh file
aks-demo: 
	./helloworld_aks_demo.sh

package: $(PACKAGE)

$(PACKAGE): $(APPDIR)
	openssl genrsa -out private.pem -3 3072
	$(MYST) package-sgx appdir private.pem config.json
	./$(PACKAGE) red green blue

run: $(APPDIR)
	@docker run --rm --device=/dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket $(DOCKER_IMG)

clean:
	@rm -rf $(APPDIR) $(MYST_TARBALL) private.pem 
