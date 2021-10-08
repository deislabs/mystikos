TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APP_NAME      = python3

APP_PATH      = /home/user/miniconda/bin/python3
PACKAGE_PATH  = myst/bin/$(APP_NAME)
ROOTFS        = ext2rootfs
TIMEOUT = 180

QUERY_INTERVAL = 2
SHUTDOWN_WAIT = 2 

all: appdir build

appdir:
	$(APPBUILDER) -v -d Dockerfile.rootfs

###########################################
## Build
###########################################

build:
	@echo "\n-------Running build-ext2--------\n"
	$(MAKE) build-ext2
	@echo "\n-------Running build-package--------\n"
	$(MAKE) build-package
	@echo "\n-------Build finished--------\n"

build-ext2: appdir
	$(MYST) mkext2 appdir $(ROOTFS)
	$(MYST) fssig --roothash $(ROOTFS) > roothash

build-package: package.pem
	$(MYST) package-sgx --roothash=roothash package.pem config.json

###########################################
## Run
###########################################

# running both service and client in one recipe
run:
	./kill.sh $(PACKAGE_PATH) $(APP_PATH)
	@echo "\n------Starting Pytorch Inference Service(package mode)------\n"
	$(PACKAGE_PATH) --rootfs=$(ROOTFS) & 
	./wait.sh

	./client.sh test_samples/dog.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg

	@sleep $(SHUTDOWN_WAIT)
	@echo "\n------Terminating Pytorch Inference Service------\n"
	./kill.sh $(PACKAGE_PATH) $(APP_PATH)

###########################################
## Misc
###########################################

package.pem:
	./gen_pkey.sh package.pem

clean:
	rm -rf appdir myst package.pem $(ROOTFS)
