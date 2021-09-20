FROM python:3.10-rc-slim
WORKDIR /app
COPY ./main.py .
RUN pip install rpdb && \
    pip install remote-pdb
ENV PYTHONUNBUFFERED=1
CMD ["/usr/local/bin/python3", "/app/main.py"]
