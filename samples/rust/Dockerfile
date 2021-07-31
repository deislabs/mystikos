FROM rust:1.53 as builder
WORKDIR /src/hello
COPY hello .
RUN cargo build --release

FROM ubuntu:18.04
RUN rm -rf /app;mkdir -p /app
COPY --from=builder /src/hello/target/release/hello /app/hello

CMD ["/app/hello"]
