CFLAGS = -fPIC

.PHONY: build run clean

all: build

build: ext2rootfs package

appdir:
	@echo "Building an appdir with all the necessary application files"
	@rm -rf appdir
	@mkdir -p appdir/bin
	gcc $(CFLAGS) -I$(MYSTIKOS_INSTALL_DIR)/include gencreds.c -o appdir/bin/gencreds

ext2rootfs: appdir
	@echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs
	@echo "Dumping roothash merkel tree"
	@myst fssig --roothash ext2rootfs > roothash

runexec: ext2rootfs
	@echo "Running application in ext2 file system with myst exec-sgx"
	@myst exec-sgx --roothash=roothash ext2rootfs /bin/gencreds $(OPTS)

package.pem:
	@echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	@echo "Generating a signed package"
	@myst package-sgx --roothash=roothash appdir package.pem config.json

run: package
	@echo "Running application outside a TEE."
	appdir/bin/gencreds
	@echo "Running Mystikos packaged application inside an SGX TEE."
	./myst/bin/gencreds

clean:
	@rm -rf appdir ext2rootfs package.pem myst roothash
