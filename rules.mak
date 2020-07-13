ifndef DIRECTORY
$(error "please define DIRECTORY variable")
endif

OBJECTS = $(SOURCES:.c=.o)
SUBOBJDIR=$(OBJDIR)/$(DIRECTORY)
__OBJECTS = $(addprefix $(SUBOBJDIR)/,$(OBJECTS))

define NL


endef

ifdef PROGRAM
__PROGRAM = $(BINDIR)/$(DIRECTORY)/$(PROGRAM)
$(__PROGRAM): dirs $(__OBJECTS)
	mkdir -p $(BINDIR)/$(DIRECTORY)
	gcc -o $(__PROGRAM) $(CFLAGS) $(__OBJECTS) $(LDFLAGS)
endif

ifdef ARCHIVE
__ARCHIVE = $(BINDIR)/$(DIRECTORY)/$(ARCHIVE)
$(__ARCHIVE): dirs $(__OBJECTS)
$(__ARCHIVE): $(__OBJECTS)
	ar rv $(__ARCHIVE) $(__OBJECTS)
endif

$(SUBOBJDIR)/%.o: %.c
	mkdir -p $(SUBOBJDIR)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

dirs:
ifdef DIRS
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )
endif

clean:
	rm -f $(__OBJECTS) $(__PROGRAM) $(__ARCHIVE) $(CLEAN)
ifdef DIRS
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
endif
