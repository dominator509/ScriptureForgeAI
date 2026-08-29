# Build from the repository root so build.rs can compile the shared proto file.
FROM rust:1.97.1-bookworm AS build

WORKDIR /workspace
COPY services/scripture-engine/Cargo.toml services/scripture-engine/Cargo.lock services/scripture-engine/build.rs ./services/scripture-engine/
COPY services/scripture-engine/src ./services/scripture-engine/src
COPY proto ./proto

WORKDIR /workspace/services/scripture-engine
RUN cargo build --release --locked

FROM debian:bookworm-slim

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd --system --uid 65532 --no-create-home scriptureforge

COPY --from=build /workspace/services/scripture-engine/target/release/scripture-engine /usr/local/bin/scriptureforge-engine
EXPOSE 50051 9102
USER scriptureforge
ENTRYPOINT ["/usr/local/bin/scriptureforge-engine"]
