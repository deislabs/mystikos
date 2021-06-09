TOP = $(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

IMG = openenclave-build

all: .openenclave
	mkdir -p $(BUILDDIR)
	rm -rf $(BUILDDIR)/openenclave
	cp -r openenclave $(BUILDDIR)/openenclave
	mkdir -p $(BUILDDIR)/bin
	rm -f $(BUILDDIR)/bin/myst-gdb
	ln -s $(BUILDDIR)/openenclave/bin/oegdb $(BUILDDIR)/bin/myst-gdb

.openenclave: .build
	$(eval INAME := $(shell docker run -d $(IMG)))
	rm -rf openenclave
	docker cp $(INAME):/work/install ./openenclave
	docker stop $(INAME) > /dev/null
	touch .openenclave

.build:
	docker build -t $(IMG) . -f Dockerfile
	touch .build

clean:
	rm -rf .openenclave .build openenclave $(BUILDDIR)/bin/myst-gdb

distclean: clean
