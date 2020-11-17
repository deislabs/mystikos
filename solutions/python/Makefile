TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(LIBOS) mkcpio appdir rootfs
run:
	$(LIBOS_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/hello_world.py

clean:
	rm -rf rootfs appdir