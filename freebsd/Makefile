TOP = $(abspath ..)
include $(TOP)/defs.mak

all:
	docker build --quiet -t myst-freebsd .

save:
	docker save -o img.tar myst-alpine

clean:
