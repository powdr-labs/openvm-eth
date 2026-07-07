#!/usr/bin/env bash
# Generate the leanr optimizer benchmark set: the TOP costliest basic blocks
# of the reth benchmark (cost = columns x execution frequency), each as
#   apc_<rank>_pc<hexpc>.json.gz            - the SymbolicMachine exactly as it
#                                             enters powdr's optimize(), with its bus map
#   apc_<rank>_pc<hexpc>.powdr_opt.json.gz  - powdr's optimized result
# plus manifest.json and apc_candidates.json (the full powdr summary). PCs in
# the file names are hex, matching the autoprecompile-analyzer. Copy the output
# dir into leanr/OpenVm/Benchmark/.
#
# The guest ELF is (re)built from source with cargo-openvm, exactly as run.sh
# does, so the block PCs match a fresh nightly build. The block witness is read
# from rpc-cache/input/1/<block>.bin; on a cache miss it is fetched automatically
# from the archive node in $RPC_1 (and cached for subsequent runs).
#
# Requirements: rustup (the pinned nightly toolchain is fetched automatically),
# cargo-openvm (to build the guest ELF), python3, >= 16 GB RAM (the PGO step
# replays the block through the OpenVM interpreter; a 4 GB machine gets
# OOM-killed), and RPC_1 (archive node) unless rpc-cache/ is already populated.
# The candidate dump is a few GB; override WORK to put it on a scratch disk.
#
# The default block is 24171377, the block the powdr nightly CI proves
# (see powdr's .github/workflows/nightly-tests.yml), so the candidate set lines
# up with the published bench-results / autoprecompile-analyzer output.
#
# Usage:            [RPC_1=<archive rpc url>] ./scripts/export_leanr_benchmark.sh
# Tunables (env):   TOP=100 OUT=leanr-benchmark WORK=<scratch dir> BLOCK=24171377
set -euo pipefail
cd "$(dirname "$0")/.."

TOP=${TOP:-100}
OUT=${OUT:-leanr-benchmark}
WORK=${WORK:-$(mktemp -d)}
BLOCK=${BLOCK:-24171377}
TARGET=${CARGO_TARGET_DIR:-target}

# The host binary loads .env via dotenv, so an RPC_1 there is enough; only bail
# out when the witness is uncached AND we have no RPC_1 from the env or .env.
if [ ! -f "rpc-cache/input/1/$BLOCK.bin" ] && [ -z "${RPC_1:-}" ] \
   && ! grep -qE '^RPC_1=' .env 2>/dev/null; then
  echo "error: no cached witness (rpc-cache/input/1/$BLOCK.bin) and RPC_1 is not set." >&2
  echo "Set RPC_1 to an Ethereum mainnet archive-node RPC URL (env or .env); the" >&2
  echo "witness is fetched once and cached for subsequent runs." >&2
  exit 1
fi

echo "== building guest ELF (cargo-openvm) — the host binary embeds it via include_bytes!"
# Same recipe as run.sh: powdr-riscv-elf needs relocation sections, and
# cargo-openvm v2 doesn't add --emit-relocs itself, so forward it via RUSTFLAGS.
# Copy only on change so include_bytes! (and thus the host binary) only rebuilds
# when the ELF actually changed.
(
  cd bin/stateless-guest
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-arg=--emit-relocs" cargo openvm build
  mkdir -p ../reth-benchmark/elf
  SRC="target/riscv32im-risc0-zkvm-elf/release/openvm-stateless-guest"
  DEST="../reth-benchmark/elf/openvm-stateless-guest"
  if [ ! -f "$DEST" ] || ! cmp -s "$SRC" "$DEST"; then
    cp "$SRC" "$DEST"
  fi
)

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
