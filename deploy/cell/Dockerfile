# One image for a cell's services (svc-log, svc-revocation, svc-evidence,
# svc-liveness, svc-verifier, svc-broker) and its tools (gen_keys, fpp-cell,
# fpp-enforce, fpp-evidence).
# docker-compose.yml runs each service as its own container. Build context:
# the repository root.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked \
        -p svc-log -p svc-revocation -p svc-evidence -p svc-liveness -p svc-verifier -p svc-broker \
        -p fpp-svc -p tools --bins

FROM debian:bookworm-slim
COPY --from=build /src/target/release/svc-log \
                  /src/target/release/svc-revocation \
                  /src/target/release/fpp-enforce \
                  /src/target/release/svc-evidence \
                  /src/target/release/fpp-evidence \
                  /src/target/release/svc-liveness \
                  /src/target/release/svc-verifier \
                  /src/target/release/svc-broker \
                  /src/target/release/fpp-cell \
                  /src/target/release/gen_keys \
                  /usr/local/bin/
RUN useradd --system --home /var/lib/fpp --shell /usr/sbin/nologin fpp \
 && install -d -o fpp -g fpp -m 0700 /var/lib/fpp /cell
USER fpp
WORKDIR /var/lib/fpp
