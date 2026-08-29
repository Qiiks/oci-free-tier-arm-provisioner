#!/usr/bin/env bash
# Oracle Cloud Always Free ARM provisioner (Rust) — launcher.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x target/release/oci-free-tier-arm ]]; then
    echo "Building release binary (first run only)..."
    cargo build --release
fi

export OCPUS="${OCPUS:-1}"
export MEMORY_GB="${MEMORY_GB:-12}"
export DISPLAY_NAME="${DISPLAY_NAME:-free-arm}"
export MAX_BACKOFF="${MAX_BACKOFF:-150}"

echo "Launching OCI ARM provisioner (1 OCPU / 12 GB)..."
echo "Press Ctrl+C to stop. It retries until capacity frees up."
echo

exec target/release/oci-free-tier-arm
