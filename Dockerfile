FROM rust:1.89-trixie@sha256:57407b378b2b6e07b48a6135a20c87cc22ea6e249c0acf6cb1833ead3cf116e9 AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/app/target cargo test --locked && cargo build --locked --release && cp target/release/motorola-receiver /usr/local/bin/motorola-receiver
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/motorola-receiver /usr/local/bin/motorola-receiver
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/motorola-receiver/
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/motorola-receiver"]
