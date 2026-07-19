FROM rust:latest AS builder

RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/smallhold

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    adduser -D -H smallhold && \
    mkdir -p /data/media && chown -R smallhold:smallhold /data

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/smallhold /usr/local/bin/smallhold

USER smallhold
WORKDIR /data

EXPOSE 8080

ENV RUST_LOG=smallhold=info

ENTRYPOINT ["smallhold"]
CMD ["serve"]
