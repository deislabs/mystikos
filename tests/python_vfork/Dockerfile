FROM python:3.10-rc-slim
WORKDIR /app
COPY ./test_vfork.py .
ENV PYTHONUNBUFFERED=1
CMD ["/usr/local/bin/python3", "/app/test_vfork.py"]
