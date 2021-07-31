TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

all: myst rootfs

rootfs: $(APPDIR)/dlopen
	$(BINDIR)/myst mkcpio appdir rootfs

$(APPDIR)/dlopen:
	mkdir -p $(APPDIR)
	cp libodbc.so.2.0.0 $(APPDIR)
	gcc -g -o $(APPDIR)/dlopen dlopen.c -ldl
	gcc -g -fPIC -shared -o $(APPDIR)/libfoo.so foo.c -ldl
	gcc -g -fPIC -shared -o $(APPDIR)/libbar.so bar.c -ldl

ifdef STRACE
OPTS = --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /dlopen $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs ramfs appdir
