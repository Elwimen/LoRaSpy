#!/usr/bin/env bash
# Build gr-lora_sdr (EPFL LoRa PHY for GNU Radio 3.10) into ./deps/prefix.
# Nothing is installed system-wide; meshsdr/grlora.py finds the local build.
# Needs: gnuradio (3.10), cmake, g++, pybind11, boost, spdlog, volk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/deps/gr-lora_sdr"
PREFIX="$ROOT/deps/prefix"
REPO="https://github.com/tapparelj/gr-lora_sdr.git"
COMMIT="${GR_LORA_SDR_COMMIT:-862746d}"   # tested with LoRaSpy

if [[ ! -d "$SRC/.git" ]]; then
    git clone "$REPO" "$SRC"
fi
git -C "$SRC" fetch --quiet origin || true
git -C "$SRC" checkout --quiet "$COMMIT" 2>/dev/null || {
    # shallow clones may lack the commit
    git -C "$SRC" fetch --quiet --unshallow origin || true
    git -C "$SRC" checkout --quiet "$COMMIT"
}

cmake -S "$SRC" -B "$SRC/build" -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_BUILD_TYPE=Release -Wno-dev
cmake --build "$SRC/build" -j"$(nproc)"
cmake --install "$SRC/build"

cd "$ROOT"
python3 -c "from meshsdr.grlora import import_lora_sdr; import_lora_sdr(); print('gr-lora_sdr OK')"
