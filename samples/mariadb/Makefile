SUBDIR = samples/mariadb
TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: libos minirootfs rootfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

mariarootfs:
	bash ./extract_maria.sh

rootfs: mariarootfs

#OPTS = --trace-syscalls

run: all
	time libos exec $(OPTS) rootfs /boot.sh

clean:
	rm -f rootfs

	