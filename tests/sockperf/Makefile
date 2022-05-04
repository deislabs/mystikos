TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

all: $(ROOTFS)
export TIMEOUT=10000

$(APPDIR):
	$(APPBUILDER) -m Dockerfile
	$(MYST_RETRY) docker build -t temp-image-for-server . -f Dockerfile_ubuntu
	# This docker image contains the compiled contents of the dockerfile that is in the same file tree here.
	# To update the image, update the dockerfile and then push a new image.
	# Then, replace this container name with the new name.

$(ROOTFS): $(APPDIR)
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

tests:
	./kill.sh
	-docker run --network="host" temp-image-for-server /app/sockperf server &
	./wait.sh
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf ping-pong
	# $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf under-load
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf throughput --msg-size=1472
	./kill.sh
	-docker run --network="host" temp-image-for-server /app/sockperf server --tcp &
	./wait.sh
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf ping-pong --tcp
	# $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf under-load --tcp
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /app/sockperf throughput --msg-size=1472 --tcp
	./kill.sh

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) sockperf
