# ============================================================
# OCI Free Tier ARM provisioner — static musl binary in scratch
# Multi-stage: cross-build for x86_64-linux-musl, ship ~2 MB image.
# ============================================================
FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

COPY src ./src
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

# ============================================================
# Runtime: scratch — no shell, no libc, nothing to patch.
# TLS root certs are compiled in (webpki-roots), no CA bundle needed.
# ============================================================
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/oci-free-tier-arm /oci-free-tier-arm

# Env is supplied at runtime (Coolify UI or docker run -e).
# Required:
#   OCI config values: see README (user/fingerprint/key PEM content/tenancy/region)
# Optional:
#   OCPUS, MEMORY_GB, DISPLAY_NAME, OS_NAME, OS_VERSION, BOOT_VOLUME_SIZE_GB,
#   MAX_RETRIES, INITIAL_BACKOFF, MAX_BACKOFF, DISCORD_WEBHOOK_URL,
#   SSH_PUBLIC_KEY (base64 of the .pub content), SLEEP_AFTER_SUCCESS

ENTRYPOINT ["/oci-free-tier-arm"]
