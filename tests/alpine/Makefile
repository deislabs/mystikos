TOP=$(abspath ../..)
include $(TOP)/defs.mak

URL=https://nl.alpinelinux.org/alpine/v3.12/releases/x86_64/alpine-minirootfs-3.12.0-x86_64.tar.gz

TARGZ=alpine-minirootfs.tar.gz

all: myst appdir rootfs

myst:
	$(MAKE) -C $(TOP)/tools/myst

appdir:
	rm -rf appdir
	mkdir -p appdir
	curl -L -o $(TARGZ) $(URL)
	( cd appdir; sudo tar zxf ../$(TARGZ); sudo chown -R `whoami` ./ )
	rm -f $(TARGZ)

rootfs:
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	TESTNAME=$(SUBDIR)-ls $(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/ls /sbin
	TESTNAME=$(SUBDIR)-pwd $(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pwd

clean:
	sudo rm -rf $(TARGZ) appdir rootfs appdir ramfs
