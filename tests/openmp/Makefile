TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

tests:
	$(MYST_EXEC) $(OPTS) rootfs /app/omp-dlopen

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /app/omp-dlopen

clean:
	rm -rf rootfs appdir
