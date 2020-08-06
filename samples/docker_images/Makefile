SUBDIR = samples/mariadb
TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: alpine nginx memcached

alpine:
	bash ./extractor.sh alpine:latest alpine.fs

nginx:
	bash ./extractor.sh nginx:alpine nginx.fs

memcached:
	bash ./extractor.sh memcached:alpine memcached.fs

clean:
	rm *.fs

run:
	libos exec $(OPTS) alpine.fs /bin/ls /bin 