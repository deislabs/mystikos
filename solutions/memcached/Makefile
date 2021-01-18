.PHONY: all app cpio

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
ifdef STRACE
OPTS = --strace
endif


all: myst cpio

#OPTS = --trace-syscalls

run: 
	@ echo -e "\n------starting memcached server------\n"
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/memcached set foo 900 9 bar

myst:
	$(MAKE) -C $(TOP)/tools/myst

app: clean
	$(TOP)/scripts/appbuilder Dockerfile

cpio: app
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs $(APPDIR)
