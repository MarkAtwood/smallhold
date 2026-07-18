FROM rust:latest AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/smallhold

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/smallhold /usr/local/bin/smallhold

RUN useradd -r -s /bin/false smallhold && mkdir -p /data/media && chown -R smallhold:smallhold /data

USER smallhold
WORKDIR /data

EXPOSE 8080

ENV RUST_LOG=smallhold=info

ENTRYPOINT ["smallhold"]
CMD ["serve"]
