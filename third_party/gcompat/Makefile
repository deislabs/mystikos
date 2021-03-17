URL=https://github.com/AdelieLinux/gcompat.git

TAG=1.0.0

all: gcompat

clean: distclean

gcompat:
	git clone $(URL) -b $(TAG)
	(cd gcompat; git apply ../patch.diff)

distclean:
	rm -rf gcompat

genpatch: gcompat
	rm -f patch.diff
	( cd gcompat; git add -A && git diff HEAD > $(CURDIR)/patch.diff )
	
