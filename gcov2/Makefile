CFLAGS += -fprofile-arcs -ftest-coverage

LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,--warn-once

all: libgcov.a

libgcov.a:
	rm -f _gcov*.o
	cp $(shell ./libname.sh) .
	./redefine.sh

clean:
	rm -f _gcov*.o libgcov.a *.gcno *.gcda
