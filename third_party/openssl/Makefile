TOP=$(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

URL=https://github.com/openssl/openssl

BRANCH=OpenSSL_1_1_1k

INSTALL_PREFIX = $(BUILDDIR)/openssl

all: .install

.install: .build
	( cd openssl; $(MAKE) install )
	touch .install

.build: .configure
	( cd openssl; $(MAKE) )
	touch .build

.configure: .openssl
	( cd openssl; ./config --prefix=$(INSTALL_PREFIX) )
	touch .configure

.openssl:
	git clone $(URL) -b $(BRANCH)
	touch .openssl

clean:
	rm -rf $(INSTALL_PREFIX) .install

distclean: clean
	rm -rf openssl .build .configure .openssl
