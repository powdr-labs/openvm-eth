#!/usr/bin/env bash
# Generate the leanr optimizer benchmark set: the TOP costliest basic blocks
# of the reth benchmark (cost = columns x execution frequency), each as
#   apc_<rank>_pc<pc>.json.gz            - the SymbolicMachine exactly as it
#                                          enters powdr's optimize(), with its bus map
#   apc_<rank>_pc<pc>.powdr_opt.json.gz  - powdr's optimized result
# plus manifest.json. Copy the output dir into leanr/OpenVm/Benchmark/.
#
# The prebuilt guest ELF is committed under bin/reth-benchmark/elf/ (on this
# branch only), so cargo-openvm is not needed. The block witness is read from
# rpc-cache/input/1/<block>.bin; on a cache miss it is fetched automatically
# from the archive node in $RPC_1 (and cached for subsequent runs).
#
# Requirements: rustup (the pinned nightly toolchain is fetched automatically),
# python3, >= 16 GB RAM (the PGO step replays the block through the OpenVM
# interpreter; a 4 GB machine gets OOM-killed), and RPC_1 (archive node) unless
# rpc-cache/ is already populated. The candidate dump is a few GB; override
# WORK to put it on a scratch disk.
#
# Usage:            [RPC_1=<archive rpc url>] ./scripts/export_leanr_benchmark.sh
# Tunables (env):   TOP=100 OUT=leanr-benchmark WORK=<scratch dir> BLOCK=23992138
set -euo pipefail
cd "$(dirname "$0")/.."

TOP=${TOP:-100}
OUT=${OUT:-leanr-benchmark}
WORK=${WORK:-$(mktemp -d)}
BLOCK=${BLOCK:-23992138}
TARGET=${CARGO_TARGET_DIR:-target}

if [ ! -f "rpc-cache/input/1/$BLOCK.bin" ] && [ -z "${RPC_1:-}" ]; then
  echo "error: no cached witness (rpc-cache/input/1/$BLOCK.bin) and RPC_1 is not set." >&2
  echo "Set RPC_1 to an Ethereum mainnet archive-node RPC URL; the witness is" >&2
  echo "fetched once and cached for subsequent runs." >&2
  exit 1
fi

echo "== building host binary (dev profile: opt-level 3, no LTO)"
CARGO_PROFILE_DEV_DEBUG=0 cargo build --bin openvm-reth-benchmark \
  --profile=dev --no-default-features --features=parallel,metrics,jemalloc,unprotected

echo "== generating APC candidates (cell PGO; interpreted replay of block $BLOCK)"
# --apc 1, not 0: --apc 0 forces PgoType::None and skips candidate generation.
# Under cell PGO the cap is ignored during generation, so ALL candidates are
# built and exported. A fresh --artifacts-dir guarantees a generate-stage cache
# miss (a cache hit would skip the export closure).
export POWDR_APC_CANDIDATES_DIR="$WORK/apcs"
"$TARGET/debug/openvm-reth-benchmark" \
  --mode compile --block-number "$BLOCK" --chain-id 1 --cache-dir rpc-cache \
  --apc 1 --apc-skip 0 --pgo-type cell --artifacts-dir "$WORK/artifacts"

echo "== selecting top $TOP by width_before x execution_frequency"
python3 scripts/select_top_candidates.py "$WORK/apcs" --out "$OUT" --top "$TOP" \
  --source "openvm-eth $(git rev-parse --short HEAD) block $BLOCK, cell PGO"

rm -rf "$WORK"
echo "Done. Copy $OUT/ into leanr/OpenVm/Benchmark/ and run e.g.:"
echo "  lake exe leanr compare --iters 64 OpenVm/Benchmark/apc_001_pc*.json.gz OpenVm/Benchmark/apc_001_pc*.powdr_opt.json.gz"
