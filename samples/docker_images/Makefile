TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

all: alpine nginx memcached redis

alpine:
	$(APPBUILDER) alpine:latest
	mv appdir alpine-appdir

nginx:
	$(APPBUILDER) nginx:alpine
	mv appdir nginx-appdir

memcached:
	$(APPBUILDER) memcached:alpine
	mv appdir memcached-appdir

redis:
	cd redis-docker; $(APPBUILDER) Dockerfile
	mv redis-docker/appdir redis-appdir

clean:
	rm -rf alpine-appdir
	rm -rf nginx-appdir
	rm -rf memcached-appdir
	rm -rf redis-appdir
	rm -rf rootfs

run:
	$(LIBOS) mkcpio alpine-appdir rootfs && $(LIBOS_EXEC) $(OPTS) rootfs /bin/ls /bin
	#$(LIBOS) mkcpio nginx-appdir rootfs && $(LIBOS) exec $(OPTS) rootfs /usr/sbin/nginx
