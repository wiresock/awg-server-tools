# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1.78-slim AS builder

WORKDIR /build

# Cache dependency compilation separately from application code.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked
RUN rm -f target/release/deps/amneziawg_web*

# Build the real application.
COPY . .
RUN cargo build --release --locked

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Create a dedicated non-root user.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin awg-web

# Install CA certificates (needed for outbound TLS if ever added).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy binary.
COPY --from=builder /build/target/release/amneziawg-web /usr/local/bin/amneziawg-web

# Runtime directory for the SQLite database.
RUN install -d -m 0700 -o awg-web -g awg-web /data

USER awg-web
WORKDIR /data

# Default environment (override at runtime via -e or --env-file).
ENV AWG_WEB_LISTEN=0.0.0.0:8080 \
    AWG_WEB_DB=/data/awg-web.db \
    AWG_CONFIG_DIR=/etc/amnezia/amneziawg/clients \
    AWG_POLL_INTERVAL=30 \
    RUST_LOG=amneziawg_web=info

EXPOSE 8080

# Preserve argv and signals while making newly created SQLite files private.
# Bind mounts still require operator-provided ownership and permissions.
ENTRYPOINT ["/bin/sh", "-c", "umask 077; exec /usr/local/bin/amneziawg-web \"$@\"", "--"]
