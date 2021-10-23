CFLAGS  := -fPIC

.PHONY: build run clean

all: build

build: cpiorootfs package

appdir: ../hello.c
	echo "Building an appdir with all the necessary application files"
	@rm -rf appdir
	@mkdir -p appdir/bin
	@gcc $(CFLAGS) -o appdir/bin/hello ../hello.c

cpiorootfs: appdir
	echo "Building a cpio archive to run in Mystikos"
	@myst mkcpio appdir cpio

runexec: cpiorootfs
	echo "Running application in cpio archive with myst exec-sgx"
	@myst exec-sgx cpio /bin/hello red green blue

package.pem:
	echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem appdir
	echo "Generating a signed package"
	@myst package-sgx appdir package.pem ../config.json

run: package
	echo "Running Mystikos packaged application. No myst exec-sgx necessary"
	./myst/bin/hello red green blue

clean:
	@rm -rf appdir cpio package.pem myst
