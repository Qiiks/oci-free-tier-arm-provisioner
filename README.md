# OCI Free Tier ARM Auto-Provisioner (Rust)

A self-contained Rust binary that automatically provisions an Oracle Cloud
**Always Free** ARM instance (`VM.Standard.A1.Flex`), defaulting to **1 OCPU /
12 GB** — the free-tier maximum — and retrying until capacity frees up.

Written in Rust to use **~1.5 MB disk** and **a few MB RAM** in the background,
vs. ~50–100 MB for the Python + `oci` SDK equivalent. No `oci` CLI needed.

## What it does

1. Reads your existing `~/.oci/config` (from `oci setup config`).
2. Ensures an SSH key exists (`~/.ssh/id_rsa`), generating one if missing.
3. Discovers availability domains, reuses (or creates) a VCN + public subnet +
   internet gateway.
4. Finds the latest Canonical Ubuntu ARM image dynamically (no stale OCIDs).
5. Launches the instance, rotating across ADs, with exponential backoff
   (30s → cap, default 150s) on the expected "Out of host capacity" 500 error.
6. Waits for RUNNING, then prints the public IP + SSH command.
7. Optionally posts a Discord embed on success/failure.

It uses the OCI **Signature Version 1** auth (RSA-SHA256) implemented directly
— no external OCI SDK, no `oci` CLI.

## Setup (one time)

Install Rust (https://rustup.rs), then create your OCI credentials:

```cmd
pip install oci-cli
oci setup config
```

That writes `~/.oci/config` with your tenancy, user, region, key file path, and
fingerprint. No other setup is required.

## Run

Double-click **`run.cmd`** (Windows), or:

```bash
./run.sh          # Linux / macOS
```

First run builds the release binary (~15s), then launches.

### Customize

Edit the `set` lines in `run.cmd` (or export env vars before `run.sh`):

| Env var | Default | Meaning |
|---|---|---|
| `OCPUS` | `1` | OCPU count (free-tier max 2, hard-capped) |
| `MEMORY_GB` | `12` | RAM GB (free-tier max 12, hard-capped) |
| `DISPLAY_NAME` | `free-arm` | Instance display name |
| `OS_NAME` / `OS_VERSION` | `Canonical Ubuntu` / `22.04` | Image filter |
| `BOOT_VOLUME_SIZE_GB` | `50` | Boot volume size |
| `ASSIGN_PUBLIC_IP` | `true` | Attach a public IP |
| `INITIAL_BACKOFF` | `30` | First retry delay (seconds) |
| `MAX_BACKOFF` | `300` | Retry delay cap (seconds) |
| `MAX_RETRIES` | `0` | Retry cap; `0` = infinite |
| `DISCORD_WEBHOOK_URL` | *(empty)* | Discord webhook for notifications |
| `DRY_RUN` | `false` | Discover resources but don't launch |
| `COMPARTMENT_ID` | tenancy root | Override compartment OCID |
| `VCN_CIDR` / `SUBNET_CIDR` | `10.0.0.0/16` / `10.0.0.0/24` | Only used when creating a new VCN |

### Dry run first

```cmd
set DRY_RUN=true
run.cmd
```

Validates config + discovery without launching anything.

## Notes

- **"Out of host capacity" (HTTP 500) is expected** — the script keeps retrying
  with backoff until ARM capacity frees up. This can take hours or days in busy
  regions.
- The OCI console download appends `OCI_API_KEY` after the PEM `END` marker;
  the binary trims it, so either a console-downloaded key or a `oci setup config`
  key works.
- The build is a single static `target/release/oci-free-tier-arm.exe` (~1.5 MB).
