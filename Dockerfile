FROM rust:latest AS builder

WORKDIR /build

# Copy fedistract workspace (source crates only, skip target/)
COPY fedistract/Cargo.toml fedistract/Cargo.lock fedistract/
COPY fedistract/cavage-httpsig/ fedistract/cavage-httpsig/
COPY fedistract/fedi-did/ fedistract/fedi-did/
COPY fedistract/fedi-e2ee/ fedistract/fedi-e2ee/
COPY fedistract/fedi-integrity/ fedistract/fedi-integrity/
COPY fedistract/fedi-provenance/ fedistract/fedi-provenance/
COPY fedistract/fedi-ucan/ fedistract/fedi-ucan/
COPY fedistract/fieldwork/ fedistract/fieldwork/
COPY fedistract/fieldwork-db/ fedistract/fieldwork-db/
COPY fedistract/ssrf-guard/ fedistract/ssrf-guard/

# Copy smallhold
COPY smallhold/Cargo.toml smallhold/Cargo.lock smallhold/
COPY smallhold/src/ smallhold/src/

WORKDIR /build/smallhold
RUN cargo build --release && strip target/release/smallhold

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/smallhold/target/release/smallhold /smallhold

EXPOSE 8080

ENV RUST_LOG=smallhold=info

ENTRYPOINT ["/smallhold"]
CMD ["serve"]
