TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs
ROOTHASH=$(CURDIR)/roothash

all: clean myst $(APPDIR) $(ROOTFS) $(ROOTHASH)

$(APPDIR):
	$(APPBUILDER) Dockerfile
	docker build -t temp-image-for-server . -f Dockerfile_ubuntu
	# This docker image contains the compiled contents of the dockerfile that is in the same file tree here.
	# To update the image, update the dockerfile and then push a new image.
	# Then, replace this container name with the new name.

$(ROOTFS):
	sudo $(MYST) mkext2 $(APPDIR) $(ROOTFS)

$(ROOTHASH):
	mkdir -p $(SUBOBJDIR)
	$(MYST) fssig --roothash $(ROOTFS) > $(ROOTHASH)

OPTS += --roothash=$(ROOTHASH)

tests:
	docker run --network="host" temp-image-for-server /app/sockperf server&
	echo "Server created"
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf ping-pong 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf under-load
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf throughput --msg-size=1472
	docker run --network="host" temp-image-for-server /app/sockperf server --tcp &
	echo "Server created"
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf ping-pong --tcp 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf under-load --tcp 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf throughput --msg-size=1472 --tcp

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) $(ROOTHASH) sockperf
