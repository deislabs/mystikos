TOP=$(abspath ..)
include $(TOP)/defs.mak

CFLAGS += -Wall -Werror $(GCOV_CFLAGS)

LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,--warn-once

LIBMYSTGCOV=$(LIBDIR)/libmystgcov.a
LIBMYSTGCOVCLIENT=$(LIBDIR)/libmystgcovclient.a
LIBMYSTGCOVSERVER=$(LIBDIR)/libmystgcovserver.a
SAMPLE=$(SUBBINDIR)/sample

INCLUDES = -I$(INCDIR)

all: $(LIBMYSTGCOV) $(LIBMYSTGCOVCLIENT) $(LIBMYSTGCOVSERVER) $(SAMPLE)

$(LIBMYSTGCOV):
	mkdir -p $(LIBDIR) $(SUBOBJDIR)
	./mklibmystgcov.sh $(LIBMYSTGCOV)

$(LIBMYSTGCOVCLIENT): gcovclient.c
	mkdir -p $(LIBDIR) $(SUBOBJDIR)
	$(CC) -Wall -Werror -c gcovclient.c -o $(SUBOBJDIR)/gcovclient.o $(INCLUDES) 
	ar rv $(LIBMYSTGCOVCLIENT) $(SUBOBJDIR)/gcovclient.o

$(LIBMYSTGCOVSERVER): gcovserver.c
	mkdir -p $(LIBDIR) $(SUBOBJDIR)
	$(CC) -Wall -Werror -c gcovserver.c -o $(SUBOBJDIR)/gcovserver.o $(INCLUDES) 
	ar rv $(LIBMYSTGCOVSERVER) $(SUBOBJDIR)/gcovserver.o

$(SAMPLE): sample.c $(LIBMYSTGCOV) $(LIBMYSTGCOVCLIENT) $(LIBMYSTGCOVSERVER)
	mkdir -p $(SUBBINDIR)
	$(CC) -g -O0 -o $(SAMPLE) $(CFLAGS) sample.c $(LIBMYSTGCOV) $(LIBMYSTGCOVCLIENT) $(LIBMYSTGCOVSERVER) $(INCLUDES) 

tests:
	$(SAMPLE)
	gcov -bc sample
	cat sample.c.gcov

CLEAN = *.o *.gcno *.gcda $(SAMPLE)
CLEAN += $(SUBBINDIR)/sample
CLEAN += $(LIBMYSTGCOV)
CLEAN += $(LIBMYSTGCOVCLIENT)
CLEAN += $(LIBMYSTGCOVSERVER)

clean:
	rm -f $(CLEAN)
