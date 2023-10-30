FROM python:3.11-alpine

RUN apk add --update --no-cache python3-dev build-base pcre-dev linux-headers
RUN pip install flask uwsgi

WORKDIR /app
COPY ./flask_app.py .
COPY ./uwsgi_app.py .
COPY ./uwsgi.ini .

ENV PYTHONUNBUFFERED=1
