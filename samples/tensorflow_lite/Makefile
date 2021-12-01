ifdef STRACE
	OPTS = --strace
endif

.PHONY: build run clean

all: build

build:  ext2rootfs package

appdir:
	@echo "Creating an appdir from Dockerfile"
	@myst-appbuilder Dockerfile.slim.buster

ext2rootfs: appdir
	@echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs
	@echo "Dumping roothash merkel tree"
	@myst fssig --roothash ext2rootfs > roothash

runexec: ext2rootfs
	@echo "Running application in ext2 file system with myst exec-sgx"
	@myst exec-sgx $(OPTS) --roothash=roothash ext2rootfs /usr/local/bin/python3 --app-config-path config.json

package.pem:
	@echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	@echo "Generating a signed package"
	@myst package-sgx --roothash=roothash package.pem config.json

run: package
	@echo "Running Mystikos packaged application. No myst exec-sgx necessary"
	./myst/bin/python3 --rootfs=ext2rootfs $(OPTS)

clean:
	@rm -rf appdir ext2rootfs package.pem  myst roothash
