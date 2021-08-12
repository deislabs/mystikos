TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: myst app

app:
	objcopy --redefine-syms=redefine.syms $(BUILDDIR)/musl/lib/libc.a musl-libc.a
	$(CC) musl-vs-libm.c musl-libc.a -lm -o app

tests:
	./app

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf musl-libc.a app
