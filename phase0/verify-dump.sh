#!/usr/bin/env bash
# Live verification of `filewallctl dump` against a freshly-built daemon.
# Rebuilds, restarts filewalld so it binds the new control socket, then dumps.
# Run with: sudo ./phase0/verify-dump.sh   (or step through it yourself)
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== building release ==="
cargo build --release

echo "=== restarting filewalld so it binds the control socket ==="
sudo systemctl stop filewalld 2>/dev/null || sudo pkill -f '/usr/bin/filewalld' || true
sudo install -m755 target/release/filewalld /usr/bin/filewalld
if systemctl list-unit-files filewalld.service >/dev/null 2>&1; then
  sudo systemctl start filewalld
else
  sudo /usr/bin/filewalld /etc/filewall/config.toml &
fi

sleep 1
echo "=== control socket ==="
ls -l /run/filewall/control.sock

echo "=== dump (table) ==="
./target/release/filewallctl dump

echo "=== dump (json, first 40 lines) ==="
./target/release/filewallctl dump --json | head -40
