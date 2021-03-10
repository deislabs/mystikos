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
	sudo $(MYST) mkext2 appdir rootfs
	$(MYST) fssig --roothash rootfs > roothash

# run w/ default settings will yield to out of memory error. Must run with config file
# to allocate larger size of memory
run:
	$(MYST_EXEC) $(OPTS) --roothash=roothash rootfs /usr/local/bin/python3 /app/mnist_convnet.py --user-mem-size 3096m

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --roothash=roothash rootfs /usr/local/bin/python3 /app/mnist_convnet.py --user-mem-size 2048m

clean:
	rm -rf rootfs appdir
