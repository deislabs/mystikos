TOP=$(abspath ../../.. )
include $(TOP)/defs.mak

PREFIX=$(TOP)/build/musl

MUSL_SRCDIR=$(BUILDDIR)/pristine-musl

all: $(MUSL_SRCDIR) $(MUSL_SRCDIR)/config.mak
	( cd $(MUSL_SRCDIR); make )
	( cd $(MUSL_SRCDIR); make install )

clean:
	rm -rf $(MUSL_SRCDIR)

distclean: clean

$(MUSL_SRCDIR)/config.mak:
	( cd $(MUSL_SRCDIR); ./configure --prefix=$(PREFIX) )

$(MUSL_SRCDIR):
	rm -rf $(MUSL_SRCDIR)
	mkdir -p $(BUILDDIR)
	cp -r ../musl $(MUSL_SRCDIR)

tests:
