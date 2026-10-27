# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Run the agmi at-rest edits against RIC stores and print the scorecard.

The edits, the landed checks (control C3) and the verdict words come from
agmi unchanged, so a ricproof cell means exactly what an agmi cell means:
rejected (the store refused the edit on its read path), reported (its audit
call named it), accepted (it served the edit as genuine), n/a (the edit
does not apply to this store, with the reason), error (the edit did not
land as intended; the harness, not the store, is at fault).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import platform
import sys

from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE
from agmi.full_runner import _verdict
from agmi.runner import run_matrix

import ricproof

#: Only rows that have been measured end to end appear here. A store that
#: has not been run does not get a row of n/a cells; it is described in
#: docs/rows.md until its adapter is built and measured.
ROWS: dict[str, str] = {
    "oran-sc-sdl": "ricproof.adapters.oran_sc_sdl:OranScSdlAdapter",
    "nonrtric-a1pms-filestore": "ricproof.adapters.nonrtric_a1pms:NonRtRicA1PmsFileStoreAdapter",
}


def _load(spec: str):
    mod, cls = spec.split(":")
    import importlib
    return getattr(importlib.import_module(mod), cls)()


def measure(targets: list[str]) -> dict:
    attacks = [cls() for cls in AT_REST_ATTACKS_WITH_ERASE]
    adapters = [_load(ROWS[t]) for t in targets]
    results = run_matrix(adapters, attacks)
    rows = []
    for adapter in adapters:
        cells = {}
        for r in results:
            if r.tool != adapter.name:
                continue
            cells[r.attack] = {
                "status": r.status,
                "verdict": _verdict(r.status, False, adapter.detection_point),
                "detail": r.guard or r.error or r.detail or "",
                "attack_version": r.version,
            }
        try:
            measured_on = adapter.measured_on()
        except Exception as exc:  # noqa: BLE001
            measured_on = f"not measured: {exc}"
        rows.append({"tool": adapter.name, "measured_on": measured_on,
                     "detection_point": adapter.detection_point, "cells": cells})
    return {
        "suite": "ricproof", "version": ricproof.__version__,
        "method": "agmi at-rest edits T1 to T10, verdict words per draft-khandelwal-bmwg-agent-memory-integrity",
        "date": _dt.date.today().isoformat(),
        "platform": f"{platform.system()} {platform.release()} Python {platform.python_version()}",
        "attacks": [{"name": a.name, "version": a.version, "description": a.description} for a in attacks],
        "rows": rows,
    }


def format_table(run: dict) -> str:
    names = [a["name"] for a in run["attacks"]]
    w = max(len(n) for n in names)
    tw = max(len(r["tool"]) for r in run["rows"]) if run["rows"] else 8
    lines = [" " * tw + " | " + " | ".join(n.center(w) for n in names)]
    lines.append("-" * len(lines[0]))
    for row in run["rows"]:
        cells = [row["cells"].get(n, {}).get("verdict", "?").center(w) for n in names]
        lines.append(row["tool"].ljust(tw) + " | " + " | ".join(cells))
    for row in run["rows"]:
        lines.append(f"\n{row['tool']}: measured on {row['measured_on']}; detection point {row['detection_point']}")
        for n in names:
            c = row["cells"].get(n)
            if c and c["detail"]:
                lines.append(f"  {n}: {c['verdict']} ({c['detail']})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ricproof")
    p.add_argument("--target", action="append", choices=sorted(ROWS), help="row to measure (repeatable); default: all")
    p.add_argument("--json", help="write the run to this path")
    args = p.parse_args(argv)
    targets = args.target or sorted(ROWS)
    run = measure(targets)
    print(format_table(run))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(run, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
