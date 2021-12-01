ifdef STRACE
	OPTS = --strace
endif

all: build

build: ext2rootfs package

appdir:
	@myst-appbuilder Dockerfile

ext2rootfs: appdir
	@echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs
	@echo "Dumping roothash merkel tree"
	@myst fssig --roothash ext2rootfs > roothash

runexec: ext2rootfs
	@echo "Running application in ext2 file system with myst exec-sgx"
	@myst exec-sgx $(OPTS) ext2rootfs /app/hello

package.pem:
	@echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	@echo "Generating a signed package"
	@myst package-sgx --roothash=roothash package.pem config.json

run: package
	@echo "Running Mystikos packaged application. No myst exec-sgx necessary"
	./myst/bin/hello --rootfs=ext2rootfs $(OPTS)

clean:
	@rm -rf appdir ext2rootfs package.pem  myst roothash