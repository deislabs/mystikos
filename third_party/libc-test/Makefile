HASH=b589b3c1876c1ecc09a5f7f34b7bcde2e2540054

all: libc-test

libc-test:
	git clone git://repo.or.cz/libc-test
	( cd libc-test git reset --hard $(HASH) )

clean:

distclean:
	rm -rf libc-test
