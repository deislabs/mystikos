TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -O3
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

LIBS += $(LIBDIR)/libmystext2.a
LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a
LDFLAGS = -lcrypto

all: rootfs bigfile

rootfs: appdir
	sudo $(MYST) mkext2 --force appdir rootfs

truncate:
	truncate --size=-4096 rootfs

FILESIZE=16777216
#FILESIZE=134217728
#FILESIZE=1073741824

appdir:
	mkdir -p appdir
	head -c $(FILESIZE) /dev/urandom > ./appdir/bigfile

bigfile: bigfile.c $(LIBS)
	gcc -I$(INCDIR) -c bigfile.c
	gcc -I$(INCDIR) -c -o sha256.o ../../target/shared/sha256.c
	gcc -I$(INCDIR) -o bigfile bigfile.o sha256.o $(LIBS) $(LDFLAGS)

tests:
	./bigfile rootfs

gdb:
	gdb --args ./bigfile rootfs

clean:
	rm -rf $(APPDIR) rootfs bigfile cachegrind.out *.o

cg:
	valgrind --tool=callgrind --callgrind-out-file=callgrind.out ./bigfile rootfs

ann:
	callgrind_annotate --auto=yes --include=$(TOP)/utils --include=$(TOP)/ext2 callgrind.out
