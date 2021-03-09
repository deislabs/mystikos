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

run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/bin/python3 /app/torch_nn.py
	# $(MYST_EXEC) $(OPTS) rootfs /usr/bin/python3 /app/torch_nn.py --app-config-path config.json

clean:
	rm -rf rootfs appdir