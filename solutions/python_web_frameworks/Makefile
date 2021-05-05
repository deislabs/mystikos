TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS = --memory-size=1024m

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(MYST) mkcpio appdir rootfs

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	@echo "===start flask server"
	@$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/flask_app.py & echo $$! > server.pid
	@sleep 10
	curl 127.0.0.1:8000 -w "\n"
	@echo "===stop flask server"
	@test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	@echo "===start uwsgi server"
	@$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/uwsgi /app/uwsgi.ini & echo $$! > server.pid
	@sleep 10
	curl 127.0.0.1:8000 -w "\n"
	@test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	@echo "===stop flask server"

server-flask:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/flask_app.py

server-uwsgi:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/uwsgi /app/uwsgi.ini

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf rootfs appdir server.pid
