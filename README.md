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

## Docker / Coolify

The container is a multi-stage musl static build shipped in a `scratch` image
(~2 MB, no shell, no libc, nothing to patch). TLS roots are compiled in.

All credentials come from env — no config file, no key file, no ssh-keygen:

| Env | Meaning |
|---|---|
| `OCI_CLI_USER` / `OCI_CLI_TENANCY` / `OCI_CLI_REGION` / `OCI_CLI_FINGERPRINT` | Same values as `~/.oci/config` |
| `OCI_CLI_KEY_CONTENT` | Full PEM body of the private key (newlines included) |
| `SSH_PUBLIC_KEY` | Content of your `id_rsa.pub` |
| `SLEEP_AFTER_SUCCESS` | Seconds to sleep after success so the container stays up (default 0 = exit) |

### Coolify (recommended)

1. Push this repo (or import it from your fork).
2. In Coolify: **New Resource → Docker Compose**, point it at `docker-compose.yml`.
3. In the env editor set: `OCI_CLI_USER`, `OCI_CLI_TENANCY`, `OCI_CLI_REGION`,
   `OCI_CLI_FINGERPRINT`, `OCI_CLI_KEY_CONTENT`, `SSH_PUBLIC_KEY`,
   `DISCORD_WEBHOOK_URL`.
4. Deploy. The container loops forever — on success it posts the green Discord
   embed, prints the IP, then sleeps (see `SLEEP_AFTER_SUCCESS`).

### Plain docker

```bash
docker build -t oci-provisioner .
docker run -d --name oci-provisioner --restart unless-stopped \
  -e OCI_CLI_USER=ocid1.user.oc1..xxx \
  -e OCI_CLI_TENANCY=ocid1.tenancy.oc1..xxx \
  -e OCI_CLI_REGION=ap-kulai-2 \
  -e OCI_CLI_FINGERPRINT=aa:bb:... \
  -e OCI_CLI_KEY_CONTENT="$(cat ~/.oci/key.pem)" \
  -e SSH_PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" \
  -e DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
  oci-provisioner
```

Local env-mode works identically (`OCI_CLI_*` env vars take priority over
`~/.oci/config`), so you can dry-run the container config without Docker:

```cmd
set OCI_CLI_USER=...
set DRY_RUN=true
target\release\oci-free-tier-arm.exe
```
