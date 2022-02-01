include hash.mak

all: libc-test

libc-test:
	git clone https://github.com/AssemblyScript/libc-test
	( cd libc-test; git reset --hard $(HASH) )

clean:

distclean:
	rm -rf libc-test
