FROM rust:latest AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/smallhold

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/smallhold /smallhold

EXPOSE 8080

ENV RUST_LOG=smallhold=info

ENTRYPOINT ["/smallhold"]
CMD ["serve"]
