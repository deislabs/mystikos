export LD_LIBRARY_PATH=$(CURDIR)/rootfs/lib

all:
	@mkdir -p rootfs/bin
	@mkdir -p rootfs/lib
	@musl-gcc -fPIC -shared -o rootfs/lib/libfoo.so foo.c
	@musl-gcc -fPIC -o rootfs/bin/main main.c -Wl,-rpath=/lib -L./rootfs/lib -lfoo

#TRACE_SYSCALLS=--trace-syscalls

run: all
	oelrun $(TRACE_SYSCALLS) rootfs /bin/main

clean:
	rm -rf rootfs
