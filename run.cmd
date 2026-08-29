@echo off
REM Oracle Cloud Always Free ARM provisioner (Rust) — double-click launcher.
cd /d "%~dp0"

REM Build the release binary if missing.
if not exist "target\release\oci-free-tier-arm.exe" (
    echo Building release binary ^(first run only^)...
    cargo build --release || goto :err
)

echo.
echo Launching OCI ARM provisioner ^(1 OCPU / 12 GB^)...
echo Press Ctrl+C to stop. It retries until capacity frees up.
echo.

REM Defaults: 1 OCPU / 12 GB (Always Free max). Override by editing the set lines below.
set "OCPUS=1"
set "MEMORY_GB=12"
set "DISPLAY_NAME=free-arm"
set "MAX_BACKOFF=150"

REM Discord webhook for success/failure notifications (pre-filled):
set "DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1542885968011329590/l2Et_2QBXCVto7xDLwCPjSid-vZFvqolUBMepjJYNJH4QYNZhWL-EVvwTmlhNjtCrYqZ"

target\release\oci-free-tier-arm.exe
goto :eof

:err
echo.
echo Build failed. Is Rust installed? https://rustup.rs
pause
