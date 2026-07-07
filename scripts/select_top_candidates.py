#!/usr/bin/env python3
"""Select the top-N costliest APC candidates from a candidates dir and package
them as a gzipped benchmark set (e.g. for the leanr optimizer benchmark).

Input: a directory populated by a run with an APC candidates dir configured
(`--apc-candidates-dir` / `POWDR_APC_CANDIDATES_DIR`), containing
`apc_candidates.json` (the aggregate summary, JSON_EXPORT_VERSION 4) and the
per-candidate exports `apc_candidate_<pcs>_000_unopt.json` (the SymbolicMachine
exactly as it enters optimize(), with its bus map) and
`apc_candidate_<pcs>_001.json` (the optimized result).

Output: `<out>/apc_<rank>_pc<hex_pcs>.json.gz` (unopt) and
`<out>/apc_<rank>_pc<hex_pcs>.powdr_opt.json.gz` (optimized) for the top N
candidates by cost, where <hex_pcs> is the block's start PC(s) in hex (matching
the autoprecompile-analyzer, which addresses blocks as e.g. 0x4ed070). Also
writes `<out>/manifest.json` with the ranking metadata and `<out>/
apc_candidates.json` (the full powdr summary verbatim, for reference).

The .powdr_opt export is the machine as `optimize()` returned it, i.e. *before*
powdr's add_guards() step, so it brackets optimize() together with the unopt
input. powdr's per-candidate `_001` file is captured after add_guards(), so we
undo that step here: every `is_valid` reference is injected by add_guards (the
pre-optimize machine has none), so substituting is_valid -> 1, constant-folding
and dropping the constraints that vanish reconstructs the unguarded machine.
Pass --keep-guards to emit powdr's raw (guarded) `_001` instead.

Cost (default): width_before x execution_frequency — the trace cells the block
costs without an APC, matching plot_effectiveness.py's weighted cost axis.

Uses only the stdlib, so it runs anywhere.
"""

import argparse
import gzip
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

JSON_EXPORT_VERSION = 4

SORT_KEYS = {
    # per-use cost measures; all are weighted by execution_frequency
    "width_before": lambda e: e["width_before"],
    "main_columns_before": lambda e: e["stats"]["before"]["main_columns"],
    "cost_after": lambda e: e["cost_after"],
    # powdr's own selection value = (cells saved per use) x frequency; NOT re-weighted
    "value": None,
}


def candidate_stub(entry):
    """(input stub, hex PC string). The input stub matches ExportOptions::new in
    export.rs, which names per-candidate files with DECIMAL start PCs joined by
    '_'. The hex PC string is for our output file names (e.g. 0x4ed070), joined
    the same way for multi-block superblocks."""
    start_pcs = [b["start_pc"] for b in entry["original_blocks"]]
    input_stub = "apc_candidate_" + "_".join(str(pc) for pc in start_pcs)
    hex_pcs = "_".join(f"0x{pc:x}" for pc in start_pcs)
    return input_stub, hex_pcs


def gzip_file(src: Path, dst: Path):
    with open(src, "rb") as f_in, gzip.open(dst, "wb", compresslevel=9) as f_out:
        f_out.write(f_in.read())


def check_unopt(path: Path):
    with open(path) as f:
        data = json.load(f)
    for key in ("machine", "bus_map"):
        if key not in data:
            sys.exit(f"error: {path} has no '{key}' key — not an ApcWithBusMap export?")
    return data


def check_opt(path: Path, stats_after):
    with open(path) as f:
        data = json.load(f)
    machine = data["machine"]
    got = (len(machine["constraints"]), len(machine["bus_interactions"]))
    want = (stats_after["constraints"], stats_after["bus_interactions"])
    if got != want:
        sys.exit(
            f"error: {path}: (constraints, bus_interactions) = {got}, but "
            f"apc_candidates.json stats.after says {want}"
        )
    return data


def _fold(e):
    """Constant-fold an algebraic-expression tree. Nodes are [l, op, r] with op
    in {'+','-','*'} or the unary ['-', x]; leaves are ints or 'name@id' refs."""
    if not isinstance(e, list):
        return e
    if len(e) == 2 and e[0] == "-":  # unary negation
        x = _fold(e[1])
        return -x if isinstance(x, int) else ["-", x]
    if len(e) == 3:
        l, op, r = _fold(e[0]), e[1], _fold(e[2])
        if isinstance(l, int) and isinstance(r, int):
            return {"+": l + r, "-": l - r, "*": l * r}[op]
        if op == "*":
            if l == 1:
                return r
            if r == 1:
                return l
            if l == 0 or r == 0:
                return 0
        elif op == "+":
            if l == 0:
                return r
            if r == 0:
                return l
        elif op == "-":
            if r == 0:
                return l
            if l == 0:
                return -r if isinstance(r, int) else ["-", r]
        return [l, op, r]
    return e


def _subst(e, name):
    """Replace every reference `name` in the expression tree with the integer 1."""
    if isinstance(e, str):
        return 1 if e == name else e
    if isinstance(e, list):
        if len(e) == 2 and e[0] == "-":
            return ["-", _subst(e[1], name)]
        if len(e) == 3:
            return [_subst(e[0], name), e[1], _subst(e[2], name)]
    return e


def strip_is_valid_guards(machine):
    """Undo powdr's add_guards() step in place, reconstructing the machine as
    optimize() returned it. See the module docstring for why is_valid -> 1 is a
    faithful inverse. Returns True if a guard column was found and removed."""
    iv = next((name for name, method in machine.get("derived_columns", [])
               if name.split("@")[0] == "is_valid" and method == {"Constant": 1}), None)
    if iv is None:
        return False
    machine["constraints"] = [
        f for c in machine["constraints"]
        # make_bool(is_valid) and (1 - is_valid)*mult guards fold to 0 -> drop them
        if (f := _fold(_subst(c, iv))) != 0
    ]
    for b in machine["bus_interactions"]:
        b["mult"] = _fold(_subst(b["mult"], iv))
        b["args"] = [_fold(_subst(a, iv)) for a in b["args"]]
    machine["derived_columns"] = [dc for dc in machine["derived_columns"] if dc[0] != iv]
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates_dir", type=Path,
                        help="directory with apc_candidates.json + per-candidate exports")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--top", type=int, default=100, help="number of candidates (default 100)")
    parser.add_argument("--sort-key", choices=sorted(SORT_KEYS), default="width_before",
                        help="cost measure; all except 'value' are multiplied by "
                             "execution_frequency (default: width_before)")
    parser.add_argument("--source", default="", help="free-text provenance note for the manifest "
                        "(e.g. 'openvm-eth block 23992138, powdr <sha>')")
    parser.add_argument("--keep-guards", action="store_true",
                        help="emit powdr's raw _001 (after add_guards) as .powdr_opt instead of "
                             "reconstructing the pre-add_guards optimize() output")
    args = parser.parse_args()

    summary_path = args.candidates_dir / "apc_candidates.json"
    with open(summary_path) as f:
        summary = json.load(f)
    if summary.get("version") != JSON_EXPORT_VERSION:
        sys.exit(f"error: {summary_path} has version {summary.get('version')}, "
                 f"expected {JSON_EXPORT_VERSION}")

    labels = summary.get("labels", {})

    if args.sort_key == "value":
        def cost(e):
            return e["value"]
    else:
        key_fn = SORT_KEYS[args.sort_key]

        def cost(e):
            return key_fn(e) * e["execution_frequency"]

    ranked = sorted(summary["apcs"], key=cost, reverse=True)
    selected = ranked[: args.top]
    if len(selected) < args.top:
        print(f"note: only {len(selected)} candidates available (asked for {args.top})")

    args.out.mkdir(parents=True, exist_ok=True)
    # Clear our own previous exports so a re-run (e.g. with different PCs after an
    # ELF rebuild) doesn't leave stale files behind. Only touch files we produce.
    for stale in [*args.out.glob("apc_*_pc*.json.gz"), args.out / "apc_candidates.json",
                  args.out / "apc_candidates.json.gz", args.out / "manifest.json"]:
        stale.unlink(missing_ok=True)

    entries = []
    for rank, entry in enumerate(selected, start=1):
        stub, hex_pcs = candidate_stub(entry)
        unopt_src = args.candidates_dir / f"{stub}_000_unopt.json"
        opt_src = args.candidates_dir / f"{stub}_001.json"
        for src in (unopt_src, opt_src):
            if not src.exists():
                sys.exit(f"error: missing per-candidate export {src}")
        check_unopt(unopt_src)
        opt = check_opt(opt_src, entry["stats"]["after"])
        # By default reconstruct the pre-add_guards optimize() output so the opt
        # snapshot brackets optimize() together with the unopt input.
        if not args.keep_guards:
            if not strip_is_valid_guards(opt["machine"]):
                sys.exit(f"error: {opt_src}: no is_valid guard column found to strip "
                         "(use --keep-guards if this export predates add_guards)")
            # optimize()'s output carries no optimistic constraints (Apc::new adds
            # them after add_guards), so match the empty form of the unopt input.
            opt["optimistic_constraints"] = {k: {} for k in opt.get("optimistic_constraints", {})}

        unopt_dst = args.out / f"apc_{rank:03d}_pc{hex_pcs}.json.gz"
        opt_dst = args.out / f"apc_{rank:03d}_pc{hex_pcs}.powdr_opt.json.gz"
        gzip_file(unopt_src, unopt_dst)
        with gzip.open(opt_dst, "wt", compresslevel=9) as f:
            json.dump(opt, f)

        opt_machine = opt["machine"]
        start_pcs = [b["start_pc"] for b in entry["original_blocks"]]
        entries.append({
            "rank": rank,
            "start_pcs": start_pcs,
            "start_pcs_hex": [f"0x{pc:x}" for pc in start_pcs],
            "files": {"unopt": unopt_dst.name, "powdr_opt": opt_dst.name},
            "cost": cost(entry),
            "execution_frequency": entry["execution_frequency"],
            "width_before": entry["width_before"],
            "cost_before": entry["cost_before"],
            "cost_after": entry["cost_after"],
            "value": entry["value"],
            "stats": entry["stats"],
            # stats["after"] is powdr's guarded count; record what we actually emit.
            "powdr_opt_stats": {
                "constraints": len(opt_machine["constraints"]),
                "bus_interactions": len(opt_machine["bus_interactions"]),
            },
            "labels": [label for pc in start_pcs for label in labels.get(str(pc), [])],
        })

    manifest = {
        "version": 1,
        "source": {
            "note": args.source,
            "sort_key": args.sort_key,
            "top": args.top,
            "candidates_available": len(summary["apcs"]),
            "powdr_opt_stage": ("after add_guards (raw powdr _001)" if args.keep_guards
                                else "after optimize(), before add_guards (is_valid guards stripped)"),
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "entries": entries,
    }
    with open(args.out / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Ship the full powdr summary too (uncompressed, so it can be loaded straight
    # into the autoprecompile-analyzer), so the exact input the ranking was
    # derived from is available.
    shutil.copyfile(summary_path, args.out / "apc_candidates.json")

    print(f"wrote {2 * len(selected)} files + manifest.json + apc_candidates.json "
          f"to {args.out} (sort key: {args.sort_key})")


if __name__ == "__main__":
    main()
