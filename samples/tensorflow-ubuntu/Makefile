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
	$(MYST) mkcpio appdir rootfs

# run w/ default settings will yield to out of memory error. Must run with config file
# to allocate larger size of memory
run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/mnist_convnet.py --app-config-path config.json

clean:
	rm -rf rootfs appdir
