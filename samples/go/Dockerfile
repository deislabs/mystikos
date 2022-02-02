FROM golang

RUN mkdir /app

COPY hello.go /app

RUN go install -buildmode=shared std

WORKDIR /app

RUN go build -linkshared hello.go
