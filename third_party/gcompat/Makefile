URL=https://github.com/jxyang/gcompat.git

TAG=1.0.0

all: gcompat

clean: distclean

gcompat:

distclean:

genpatch: gcompat
	rm -f patch.diff
	( cd gcompat; git add -A && git diff HEAD > $(CURDIR)/patch.diff )
	
