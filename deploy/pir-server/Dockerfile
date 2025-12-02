FROM rustlang/rust:nightly as builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --bin pir_server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pir_server /usr/local/bin/
EXPOSE 8080
CMD ["pir_server", "--database", "/data/pir.db", "--listen", "0.0.0.0:8080", "serve"]