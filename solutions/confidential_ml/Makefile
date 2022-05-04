TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APP_NAME      = python3

APP_PATH      = /usr/local/bin/python3
PACKAGE  = myst/bin/$(APP_NAME)

QUERY_INTERVAL = 2
SHUTDOWN_WAIT = 2 

all: $(PACKAGE)

appdir:
	$(APPBUILDER) -m -d Dockerfile

$(PACKAGE): appdir package.pem
	$(MYST) mkext2 appdir rootfs
	$(MYST) fssig --roothash rootfs > roothash
	$(MYST) package-sgx --roothash=roothash package.pem config.json

# running both service and client in one recipe
_run:
	./kill.sh $(PACKAGE) $(APP_PATH)
	@echo "\n------Starting Pytorch Inference Service(package mode)------\n"
	$(PACKAGE) --rootfs=rootfs &
	./wait.sh

	./client.sh test_samples/dog.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg

	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/dog.jpg.encrypted
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg.encrypted
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg.encrypted

	@sleep $(SHUTDOWN_WAIT)
	@echo "\n------Terminating Pytorch Inference Service------\n"
	./kill.sh $(PACKAGE) $(APP_PATH)
	
run:
	$(RUNTEST) make -C $(CURDIR) _run

package.pem:
	./gen_pkey.sh package.pem

clean:
	rm -rf appdir myst package.pem rootfs roothash
