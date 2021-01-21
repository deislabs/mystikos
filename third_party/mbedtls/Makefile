TOP = $(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

INSTALL_PREFIX=$(BUILDDIR)/mbedtls

all: mbedtls
	rm -rf $(INSTALL_PREFIX)
	$(MAKE) -C mbedtls install DESTDIR=$(INSTALL_PREFIX)

clean:
	$(MAKE) -C mbedtls clean

distclean:
	rm -rf mbedtls

mbedtls:
	git clone https://github.com/ARMmbed/mbedtls -b mbedtls-2.16
