#!/usr/bin/env bash
# System packages for the sec-worker sandbox host (Ubuntu 24.04).
# Run: sudo ./bootstrap/bootstrap.sh
set -euo pipefail

apt-get update
apt-get install -y --no-install-recommends \
  bubblewrap \
  socat \
  ripgrep \
  git \
  curl \
  ca-certificates \
  python3 \
  python3-venv \
  python3-dev \
  build-essential \
  pkg-config \
  util-linux

# Kernel prerequisites for unprivileged bubblewrap sandboxing.
if [ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
  val=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
  echo "apparmor_restrict_unprivileged_userns=${val}"
  if [ "$val" = "1" ]; then
    echo "NOTE: Ubuntu 24.04 restricts unprivileged user namespaces."
    echo "Test 'bwrap --unshare-all --ro-bind / / echo ok' first; if it fails,"
    echo "add a narrow AppArmor profile for bwrap rather than disabling the sysctl globally."
  fi
fi

echo "bootstrap done"
