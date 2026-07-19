FROM clux/muslrust:stable AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/x86_64-unknown-linux-musl/release/smallhold

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/smallhold /smallhold

EXPOSE 8080

ENV RUST_LOG=smallhold=info

ENTRYPOINT ["/smallhold"]
CMD ["serve"]
