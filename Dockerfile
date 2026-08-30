# ============================================================
# OCI Free Tier ARM provisioner — static musl binary in scratch
# Multi-stage: builds natively for the host arch (x86_64 OR aarch64),
# ships a ~2 MB image. Target arch is auto-detected in the builder;
# the binary is exported to a fixed path for the runtime stage.
# ============================================================
FROM rust:1-slim AS builder

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TARGET="aarch64-unknown-linux-musl"; \
    else TARGET="x86_64-unknown-linux-musl"; fi && \
    echo "Building for target: $TARGET" && \
    apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/* && \
    rustup target add "$TARGET"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN ARCH=$(uname -m) && mkdir src && echo 'fn main() {}' > src/main.rs && \
    if [ "$ARCH" = "aarch64" ]; then cargo build --release --target aarch64-unknown-linux-musl 2>/dev/null || true; \
    else cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true; fi

COPY src ./src
RUN ARCH=$(uname -m) && touch src/main.rs && \
    if [ "$ARCH" = "aarch64" ]; then cargo build --release --target aarch64-unknown-linux-musl; \
    else cargo build --release --target x86_64-unknown-linux-musl; fi && \
    if [ "$ARCH" = "aarch64" ]; then cp target/aarch64-unknown-linux-musl/release/oci-free-tier-arm /oci-free-tier-arm; \
    else cp target/x86_64-unknown-linux-musl/release/oci-free-tier-arm /oci-free-tier-arm; fi

# ============================================================
# Runtime: scratch — no shell, no libc, nothing to patch.
# TLS root certs are compiled in (webpki-roots), no CA bundle needed.
# ============================================================
FROM scratch

COPY --from=builder /oci-free-tier-arm /oci-free-tier-arm

# Env is supplied at runtime (Coolify UI or docker run -e).
# Required:
#   OCI config values: see README (user/fingerprint/key PEM content/tenancy/region)
# Optional:
#   OCPUS, MEMORY_GB, DISPLAY_NAME, OS_NAME, OS_VERSION, BOOT_VOLUME_SIZE_GB,
#   MAX_RETRIES, INITIAL_BACKOFF, MAX_BACKOFF, DISCORD_WEBHOOK_URL,
#   SSH_PUBLIC_KEY (base64 of the .pub content), SLEEP_AFTER_SUCCESS

ENTRYPOINT ["/oci-free-tier-arm"]
