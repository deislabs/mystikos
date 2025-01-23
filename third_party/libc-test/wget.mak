include hash.mak

# Official web page for libc-test snapshot releases
WEBPAGE=http://nsz.repo.hu/git/?p=libc-test

URL="$(WEBPAGE);a=snapshot;h=$(HASH);sf=tgz"

TGZ=libc-test.tgz

all: libc-test

libc-test:
#	wget --quiet -O $(TGZ) $(URL)
#	tar zxf $(TGZ)
#	mv libc-test-* libc-test
#	rm -rf $(TGZ)

clean:

distclean:
#	rm -rf libc-test $(TGZ) libc-test-*
