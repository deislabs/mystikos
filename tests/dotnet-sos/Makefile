TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"

ifdef STRACE
OPTS += --strace
endif

all: appdir rootfs ext2fs

appdir:
	$(APPBUILDER)

rootfs:
	rm -rf appdir/tmp/clr-debug-pipe*
	$(MYST) mkcpio appdir rootfs

ext2fs:
	rm -rf appdir/tmp/clr-debug-pipe*
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs rootfs roothash /tmp/myst*

##################################
#			dev targets			 #
##################################
run-cpio:
	$(MYST) exec rootfs \
	--memory-size $(HEAP_SIZE) \
	/usr/share/dotnet/dotnet \
	/src/hello/bin/Debug/net5.0/alpine-x64/hello.dll

run-ext2:
	$(MYST) exec ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/usr/share/dotnet/dotnet \
	/src/hello/bin/Debug/net5.0/alpine-x64/hello.dll

run-ext2-lldb:
	/mnt/oelldb/oelldb -- $(MYST) exec $(OPTS) ext2fs \
	--roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/usr/share/dotnet/dotnet \
	/src/hello/bin/Debug/net5.0/alpine-x64/hello.dll

ct:
	sudo rm -fr /tmp/myst*
