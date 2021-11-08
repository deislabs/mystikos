ifdef STRACE
	OPTS = --strace
endif

.PHONY: build run clean

all: build

build:  ext2rootfs package

appdir:
	echo "Creating an appdir from Dockerfile"
	@myst-appbuilder Dockerfile

ext2rootfs: appdir
	echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs

runexec: ext2rootfs
	echo "Running application in ext2 file system with myst exec-sgx"
	@myst exec-sgx $(OPTS) ext2rootfs /app/TEEAware --app-config-path config.json

package.pem:
	echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	echo "Generating a signed package"
	@myst package-sgx appdir package.pem config.json

run: package
	echo "Running Mystikos packaged application. No myst exec-sgx necessary"
	myst/bin/TEEAware $(OPTS)

clean:
	@rm -rf appdir ext2rootfs package.pem  myst roothash TEEAware/build TEEAware/obj TEEAware/bin
