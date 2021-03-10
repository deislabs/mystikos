This is a simple demo of a basic python webserver using common frameworks.

It makes a few customizations to the standard python-3-alpine docker image,
which you can find in the Dockerfile, then loads the docker file into the `myst` runtime.

Building with `make` will yield a myst-compatible file named `hello_server.cpio`.
You can select whether to invoke the flask or uwsgi demo at run time, in essentially the same way you might
choose the container entrypoint with docker. 

See the commandline examples below, or simply exercize both with `make run`.

Flask
---

```
myst exec-sgx hello_server.cpio /usr/local/bin/python3 /app/flask_app.py
```

uWSGI
---

```
myst exec-sgx hello_server.cpio /usr/local/bin/uwsgi /app/uwsgi.ini
```
