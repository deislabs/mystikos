TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APP_NAME      = python3

ifndef APP_MODE
APP_MODE      = ext2
endif

ifeq ($(APP_MODE),ext2)
APP_PATH      = /home/user/miniconda/bin/python3
ROOTFS        = ext2rootfs
LAUNCH_WAIT   = 60
else
APP_PATH      = myst/bin/$(APP_NAME)
LAUNCH_WAIT   = 90
endif

QUERY_INTERVAL = 2
SHUTDOWN_WAIT = 2 

ifdef STRACE
OPTS = --strace
endif

all: appdir build

appdir:
	$(APPBUILDER) -v -d Dockerfile.rootfs

###########################################
## Build
###########################################

build: 
ifeq ($(APP_MODE),package)
	@echo "\n-------package build start--------\n"
	$(MAKE) build-package
else
	@echo "\n-------ext2 build start--------\n"
	$(MAKE) build-ext2
endif
	@echo "\n-------build end--------\n"

build-ext2: appdir
	sudo $(MYST) mkext2 appdir $(ROOTFS)
	sudo chown $(USER).$(USER) $(ROOTFS)
	$(MYST) fssig --roothash $(ROOTFS) > roothash

build-package: appdir package.pem
	$(MYST) package-sgx appdir package.pem config.json

###########################################
## Run
###########################################

# running both service and client in one recipe
run:
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` || true
	@echo -e "\n------starting Pytorch Inference Service($(APP_MODE) mode)------\n"
ifeq ($(APP_MODE),package)
	$(APP_PATH) $(OPTS) & echo $$! > $(APP_NAME).pid
else
	$(MYST_EXEC) $(OPTS) --roothash=roothash $(ROOTFS) $(APP_PATH) --app-config-path config.json & echo $$! > $(APP_NAME).pid
endif
	sleep $(LAUNCH_WAIT)
	@echo -e "\nRun client outside of the Enclave ...\n"
	./client.sh test_samples/dog.jpg
	sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg
	sleep $(SHUTDOWN_WAIT)
	@echo "\n------terminate Pytorch Inference Service------\n"
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` && rm $(APP_NAME).pid || true

# launch inference service in enclave only, waiting for client to connect, either 
# run a webpage, curl request or the client.sh script with predefined queries
run-service-ext2:
	$(MYST_EXEC) $(OPTS) --roothash=roothash $(ROOTFS) $(APP_PATH) --app-config-path config.json

run-service-package:
	$(APP_PATH) $(OPTS)

###########################################
## Debug
###########################################

gdb:
ifeq ($(APP_MODE),package)
	$(MYST_GDB) --args $(MYST_EXEC) $(APP_PATH)
else
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --roothash=roothash $(ROOTFS) $(APP_PATH) --app-config-path config.json
endif

###########################################
## Misc
###########################################

package.pem:
	openssl genrsa -out package.pem -3 3072

clean:
	rm -rf appdir $(APP_PATH) myst package.pem $(APP_NAME).pid $(ROOTFS) roothash
