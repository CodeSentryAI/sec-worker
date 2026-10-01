#!/usr/bin/env bash
# User-scoped toolchains for the detectors. No sudo required.
#   - nightly-2026-02-07 Rust toolchain (lockbud-stable's pin)
#   - lockbud-stable release build
#   - peCatch venv: slither-analyzer 0.9.1 + safe-pysha3 + pecatch plugins + solc-select
#
# Environment overrides:
#   LOCKBUD_STABLE_DIR   (default ~/Projects/lockbud-stable)
#   PECATCH_SOURCE_DIR   (default ~/Projects/solidity-sec/code/peCatch/code)
#   TOOLCHAINS_DIR       (default ~/sec-toolchains)
set -euo pipefail

LOCKBUD_STABLE_DIR="${LOCKBUD_STABLE_DIR:-$HOME/Projects/lockbud-stable}"
PECATCH_SOURCE_DIR="${PECATCH_SOURCE_DIR:-$HOME/Projects/solidity-sec/code/peCatch/code}"
TOOLCHAINS_DIR="${TOOLCHAINS_DIR:-$HOME/sec-toolchains}"
RUST_PIN="nightly-2026-02-07"

echo "== rust toolchain ${RUST_PIN} =="
if ! rustup toolchain list | grep -q "^${RUST_PIN}"; then
  rustup toolchain install "${RUST_PIN}" \
    --profile minimal \
    --component rust-src,rustc-dev,llvm-tools-preview,rustfmt
fi

echo "== lockbud-stable build =="
if [ ! -x "${LOCKBUD_STABLE_DIR}/target/release/lockbud-stable" ]; then
  (cd "${LOCKBUD_STABLE_DIR}" && cargo build --release)
fi
"${LOCKBUD_STABLE_DIR}/target/release/lockbud-stable" --help >/dev/null 2>&1 \
  || LD_LIBRARY_PATH="$(rustup run "${RUST_PIN}" rustc --print sysroot)/lib" \
     "${LOCKBUD_STABLE_DIR}/target/release/lockbud-stable" --help >/dev/null

echo "== peCatch venv (slither 0.9.1) =="
VENV="${TOOLCHAINS_DIR}/venv-pecatch"
if [ ! -x "${VENV}/bin/slither" ]; then
  mkdir -p "${TOOLCHAINS_DIR}"
  # --without-pip + get-pip fallback is used when python3-venv/ensurepip is absent.
  if ! python3 -m venv "${VENV}" 2>/dev/null; then
    rm -rf "${VENV}"
    python3 -m venv --without-pip "${VENV}"
    curl -sS https://bootstrap.pypa.io/get-pip.py | "${VENV}/bin/python"
  fi
  PIP="${VENV}/bin/pip"
  $PIP install --quiet --upgrade pip wheel
  # slither 0.9.1 imports pkg_resources (removed in setuptools >= 81).
  $PIP install --quiet "setuptools<81"
  # slither 0.9.1 pins pysha3 (abandoned; needs Python.h to build on py3.12).
  # safe-pysha3 ships a cp312 wheel providing the same sha3 module; a metadata-only
  # stub satisfies pkg_resources' declared pysha3>=1.0.2 distribution check.
  $PIP install --quiet safe-pysha3
  STUB_DIR="${TOOLCHAINS_DIR}/pysha3-stub"
  mkdir -p "${STUB_DIR}"
  cat > "${STUB_DIR}/setup.py" <<'STUB'
from setuptools import setup
setup(name="pysha3", version="1.0.2", py_modules=[])
STUB
  $PIP install --quiet "${STUB_DIR}"
  $PIP install --quiet --no-deps slither-analyzer==0.9.1
  $PIP install --quiet "prettytable>=0.7.2" "crytic-compile>=0.2.4" solc-select==1.0.4
  # Editable: pecatch_plugin/detectors/ lacks __init__.py, so find_packages()
  # drops the subpackage from a regular install. The worker binds the source
  # dir read-only into the sandbox at its real path (src/config.ts).
  $PIP install --quiet --no-deps -e "${PECATCH_SOURCE_DIR}"
fi
"${VENV}/bin/slither" --version

echo "== bench venv (slither 0.11.6, phase-timing benchmarks) =="
BENCH_VENV="${TOOLCHAINS_DIR}/venv-bench"
if [ ! -x "${BENCH_VENV}/bin/slither" ]; then
  if ! python3 -m venv "${BENCH_VENV}" 2>/dev/null; then
    rm -rf "${BENCH_VENV}"
    python3 -m venv --without-pip "${BENCH_VENV}"
    curl -sS https://bootstrap.pypa.io/get-pip.py | "${BENCH_VENV}/bin/python"
  fi
  BP="${BENCH_VENV}/bin/pip"
  $BP install --quiet --upgrade pip wheel
  $BP install --quiet "setuptools<81"
  $BP install --quiet slither-analyzer==0.11.6 || $BP install --quiet slither-analyzer==0.11.6.0
fi
"${BENCH_VENV}/bin/slither" --version

echo "== solc versions (offline cache) =="
"${VENV}/bin/solc-select" install 0.5.16 || true
"${VENV}/bin/solc-select" install 0.7.6 || true
"${VENV}/bin/solc-select" install 0.8.20 || true
"${VENV}/bin/solc-select" install 0.8.26 || true
"${VENV}/bin/solc-select" install 0.8.28 || true

echo "== containment self-test =="
echo "run: cd sec-worker && npm run selftest"
echo "toolchain install done"
