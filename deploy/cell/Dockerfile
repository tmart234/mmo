# Single lean image for the unified Fair-Play Protocol authority daemon (`fppd`).
# Build context: the repository root.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p fppd --bin fppd

FROM debian:bookworm-slim
COPY --from=build /src/target/release/fppd /usr/local/bin/fppd
RUN useradd --system --home /var/lib/fpp --shell /usr/sbin/nologin fpp \
 && install -d -o fpp -g fpp -m 0700 /var/lib/fpp /var/lib/fpp/cell /var/lib/fpp/keys
USER fpp
WORKDIR /var/lib/fpp
ENTRYPOINT ["fppd"]
