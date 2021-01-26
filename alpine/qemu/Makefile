##==============================================================================
##
## variables:
##
##==============================================================================

IMG=alpine-virt-3.13.0-x86_64.iso
URL=https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/$(IMG)
SIZE=4G
GCOW=apline.gcow2

all:

##==============================================================================
##
## setup:
##
##==============================================================================

.prereqs:
	sudo apt -y install qemu
	touch .prereqs

img: $(IMG)

$(IMG):
	wget $(URL)

setup: .prereqs img
	qemu-img create -f qcow2 $(GCOW) $(SIZE)
	qemu-system-x86_64 -nographic -m 512 -boot d -cdrom $(IMG) -hda $(GCOW)

##==============================================================================
##
## boot:
##
##==============================================================================

boot:
	qemu-system-x86_64 -curses -m 512 -hda $(GCOW)

##==============================================================================
##
## extract: extract the root file system as an EXT2 file system
##
##==============================================================================

extract:
	qemu-img convert -p -O raw $(GCOW) raw.img
	$(MAKE) __extract

__extract:
	@ $(eval START := $(shell fdisk -l raw.img | grep raw.img3 | awk '{ print $$2 }') )
	@ $(eval SECTORS := $(shell fdisk -l raw.img | grep raw.img3 | awk '{ print $$4 }') )
	dd if=raw.img of=ext2.img bs=512 skip=$(START) count=$(SECTORS) status=progress
	tune2fs -O ^has_journal ext2.img
	e2fsck -y ext2.img

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	rm -rf .prereqs $(IMG) ext2.img raw.img $(GCOW)

##==============================================================================
##
## run:
##
##==============================================================================

run:
	myst exec ext2.img /root/bin/hello
