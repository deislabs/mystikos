.PHONY: build run clean

APP_PATH      = /home/user/miniconda/bin/python3
PACKAGE_PATH  = myst/bin/python3
ROOTFS        = ext2rootfs
TIMEOUT = 180
ifdef STRACE
	OPTS = --strace
endif

QUERY_INTERVAL = 2
SHUTDOWN_WAIT = 2 

all: build

build:  ext2rootfs package

appdir:
	@echo "Convert Dockerfile to an appdir using myst-appbuilder."
	@myst-appbuilder -v -d Dockerfile.rootfs

ext2rootfs: appdir
	@echo "Building a ext2 file system to run in Mystikos"
	@myst mkext2 appdir ext2rootfs
	@echo "Dumping roothash merkel tree"
	@myst fssig --roothash ext2rootfs > roothash


package.pem:
	@echo "Generating a signing key"
	openssl genrsa -out package.pem -3 3072

package: package.pem ext2rootfs
	@echo "Generating a signed package"
	@myst package-sgx --roothash=roothash package.pem config.json

runexec: ext2rootfs
	./kill.sh myst exec-sgx
	@echo "Running with myst exec"
	@myst exec-sgx $(OPTS) --roothash=roothash ext2rootfs $(APP_PATH) --app-config-path config.json &
	./wait.sh
	./client.sh test_samples/dog.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg
	@sleep $(SHUTDOWN_WAIT)
	./kill.sh myst exec-sgx

run: package
	./kill.sh $(PACKAGE_PATH) $(APP_PATH)
	@echo "Running in package mode"
	$(PACKAGE_PATH) --rootfs=ext2rootfs $(OPTS)  & 
	./wait.sh
	./client.sh test_samples/dog.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg
	@sleep $(SHUTDOWN_WAIT)
	./kill.sh $(PACKAGE_PATH) $(APP_PATH)

clean:
	rm -rf appdir myst package.pem ext2rootfs
	