# ============================================================
# OCI Free Tier ARM provisioner — static musl binary in scratch
# Multi-stage: builds natively for the host arch (x86_64 OR aarch64),
# ships a ~2 MB image. TARGET is auto-detected, shared across stages.
# ============================================================
FROM rust:1-slim AS builder
ARG TARGET=x86_64-unknown-linux-musl

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then \
      if [ "$TARGET" != "aarch64-unknown-linux-musl" ]; then \
        echo "Refusing to build: TARGET=$TARGET does not match host arch $ARCH" >&2; exit 1; fi; \
    else \
      if [ "$TARGET" != "x86_64-unknown-linux-musl" ]; then \
        echo "Refusing to build: TARGET=$TARGET does not match host arch $ARCH" >&2; exit 1; fi; \
    fi && \
    apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/* && \
    rustup target add "$TARGET"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --target "$TARGET" 2>/dev/null || true

COPY src ./src
RUN touch src/main.rs && cargo build --release --target "$TARGET"

# ============================================================
# Runtime: scratch — no shell, no libc, nothing to patch.
# TLS root certs are compiled in (webpki-roots), no CA bundle needed.
# ============================================================
FROM scratch
ARG TARGET=x86_64-unknown-linux-musl

COPY --from=builder /build/target/${TARGET}/release/oci-free-tier-arm /oci-free-tier-arm

# Env is supplied at runtime (Coolify UI or docker run -e).
# Required:
#   OCI config values: see README (user/fingerprint/key PEM content/tenancy/region)
# Optional:
#   OCPUS, MEMORY_GB, DISPLAY_NAME, OS_NAME, OS_VERSION, BOOT_VOLUME_SIZE_GB,
#   MAX_RETRIES, INITIAL_BACKOFF, MAX_BACKOFF, DISCORD_WEBHOOK_URL,
#   SSH_PUBLIC_KEY (base64 of the .pub content), SLEEP_AFTER_SUCCESS

ENTRYPOINT ["/oci-free-tier-arm"]
