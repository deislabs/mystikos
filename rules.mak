ifndef SUBDIR
$(error "please define SUBDIR variable")
endif

__OBJECTS1 = $(SOURCES:.c=.o)
__OBJECTS2 = $(__OBJECTS1:.s=.o)
OBJECTS = $(__OBJECTS2:.S=.o)
__OBJECTS = $(addprefix $(SUBOBJDIR)/,$(OBJECTS))

define NL


endef

ifdef PROGRAM
__PROGRAM = $(SUBBINDIR)/$(PROGRAM)
program: $(__PROGRAM) dirs
$(__PROGRAM): $(LIBS) $(__OBJECTS)
	mkdir -p $(SUBBINDIR)
	$(CC) -o $(__PROGRAM) $(CFLAGS) $(__OBJECTS) $(LIBS) $(LDFLAGS)
	@ echo "Created $(__PROGRAM)"
endif

ifdef SHLIB
__SHLIB = $(SUBBINDIR)/$(SHLIB)
shlib: $(__SHLIB) dirs
	@echo "$(__SHLIB) is up to date"

$(__SHLIB): $(LIBS) $(__OBJECTS)
	mkdir -p $(SUBBINDIR)
	$(CC) -shared -o $(__SHLIB) $(CFLAGS) $(__OBJECTS) $(LIBS) $(LDFLAGS)
	@ echo "Created $(__SHLIB)"
endif

ifdef ARCHIVE
__ARCHIVE = $(SUBLIBDIR)/$(ARCHIVE)
archive: $(__ARCHIVE) dirs
$(__ARCHIVE): $(__OBJECTS)
	mkdir -p $(SUBLIBDIR)
	ar rv $(__ARCHIVE) $(__OBJECTS)
	@ echo "Created $(__ARCHIVE)"
endif

$(SUBOBJDIR)/%.o: %.c $(DEPENDS)
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

$(SUBOBJDIR)/%.o: %.s $(DEPENDS)
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

$(SUBOBJDIR)/%.o: %.S $(DEPENDS)
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

dirs:
ifdef DIRS
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )
endif

__clean:
	sudo rm -rf $(__OBJECTS) $(__PROGRAM) $(__SHLIB) $(__ARCHIVE) $(CLEAN)
ifdef DIRS
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
endif

ifndef REDEFINE_CLEAN
clean: __clean
endif

tests:
ifndef REDEFINE_TESTS
ifdef DIRS
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )
endif
endif
