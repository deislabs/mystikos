SUBDIR = samples/alpine
TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: libos appdir rootfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

appdir:
	curl -L -o alpine-minirootfs.tar.gz https://nl.alpinelinux.org/alpine/v3.8/releases/x86_64/alpine-minirootfs-3.8.0-x86_64.tar.gz
	rm -rf appdir
	mkdir -p appdir
	( cd appdir; sudo tar zxf ../alpine-minirootfs.tar.gz ; sudo chown -R `whoami` ./ )
	rm -f alpine-appdir.tar.gz

rootfs:
	libos mkcpio appdir rootfs

#OPTS = --trace-syscalls

run: all
	libos exec $(OPTS) rootfs /bin/ls /sbin

clean:
	sudo rm -rf alpine-minirootfs.tar.gz appdir rootfs appdir
