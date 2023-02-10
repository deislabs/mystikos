CFLAGS  := -fPIC

.PHONY: build run clean

all: build

build:  ext2rootfs package

appdir: ../hello.c
	echo "Building an appdir with all the necessary application files"
	@rm -rf appdir
	@mkdir -p appdir/bin
	@gcc $(CFLAGS) -o appdir/bin/hello ../hello.c

ext2rootfs: appdir
	echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs
	echo "Dumping roothash merkel tree"
	@myst fssig --roothash ext2rootfs > roothash

runexec: ext2rootfs
	echo "Running application in ext2 file system with myst exec-sgx"
	@myst exec-sgx --roothash=roothash ext2rootfs /bin/hello red green blue

package.pem:
	echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	echo "Generating a signed package"
	@myst package-sgx --roothash=roothash package.pem ../config.json

export MYST_ROOTFS_PATH=$(CURDIR)/ext2rootfs

run: package
	echo "Running Mystikos packaged application. No myst exec-sgx necessary"
	./myst/bin/hello red green blue

clean:
	@rm -rf appdir ext2rootfs package.pem  myst roothash
