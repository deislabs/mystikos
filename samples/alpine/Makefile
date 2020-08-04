SUBDIR = samples/alpine
TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: libos minirootfs rootfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

minirootfs:
	curl -L -o alpine-minirootfs.tar.gz https://nl.alpinelinux.org/alpine/v3.8/releases/x86_64/alpine-minirootfs-3.8.0-x86_64.tar.gz
	rm -rf minirootfs
	mkdir -p minirootfs
	( cd minirootfs; tar zxf ../alpine-minirootfs.tar.gz )
	rm -f alpine-minirootfs.tar.gz

rootfs:
	rm -rf appdir
	mkdir -p appdir/bin
	cp minirootfs/bin/busybox appdir/bin/ls
	cp -r minirootfs/sbin appdir/sbin
	( cd appdir; find . | cpio --create --format='newc' > ../rootfs )

#OPTS = --trace-syscalls

run: libos rootfs
	time libos exec $(OPTS) rootfs /bin/ls /sbin

clean:
	rm -rf alpine-minirootfs.tar.gz minirootfs rootfs appdir
