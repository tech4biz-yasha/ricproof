# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Walkthrough of the nonrtric-a1pms-filestore row with the near-RT RIC's view.

The scorecard cell records what A1PMS serves on its own read path. This
script makes three of the edits by hand, restarts the service, and prints
two things after each: what A1PMS serves, and what the near-RT RIC (the
A1 simulator A1PMS pushes policies to) holds. The second is the effect on
the RAN of an edit made beneath the non-RT RIC's file store.

Needs the same RICPROOF_A1PMS_* environment as the row, plus
RICPROOF_A1SIM_URL for the simulator that serves ric1 (e.g. http://127.0.0.1:2222)
and RICPROOF_A1PMS_TYPE (default "1").

    python experiments/a1pms_walkthrough.py
"""

from __future__ import annotations

import os

import requests

from ricproof.adapters.nonrtric_a1pms import NonRtRicA1PmsFileStoreAdapter

SIM = os.environ.get("RICPROOF_A1SIM_URL", "http://127.0.0.1:2222").rstrip("/")


def both(a: NonRtRicA1PmsFileStoreAdapter, label: str) -> None:
    pms = requests.get(f"{a._url}/a1-policy/v2/policies", params={"ric_id": a.ric}, timeout=30).json()["policy_ids"]
    ric = requests.get(f"{SIM}/a1-p/policytypes/{a._type}/policies", timeout=30).json()
    print(f"\n[{label}]")
    print(f"  A1PMS lists {sorted(pms)}")
    print(f"  near-RT RIC holds {sorted(ric)}")
    for pid in sorted(set(pms) | set(ric)):
        p = requests.get(f"{a._url}/a1-policy/v2/policies/{pid}", timeout=30)
        r = requests.get(f"{SIM}/a1-p/policytypes/{a._type}/policies/{pid}", timeout=30)
        pv = p.json()["policy_data"]["statement"]["priorityLevel"] if p.status_code == 200 else f"HTTP {p.status_code}"
        rv = r.json()["statement"]["priorityLevel"] if r.status_code == 200 else f"HTTP {r.status_code}"
        print(f"    {pid}: A1PMS priorityLevel={pv}   RIC priorityLevel={rv}")


def main() -> None:
    a = NonRtRicA1PmsFileStoreAdapter()
    a.setup()
    try:
        a.seed(3)
        both(a, "T0 seeded through PUT /a1-policy/v2/policies")

        rec = a.read_all_raw()[1]
        a.write_raw(a.mutate_payload(rec))
        a.reload()
        both(a, "T1 tamper: rp-000001 priorityLevel set to 99 in the file, service restarted")

        a.delete_raw(2)
        a.reload()
        both(a, "T2 truncate: rp-000002.json deleted beneath the service, service restarted")

        a.write_raw(a.forge_record(a.read_all_raw()[-1]))
        a.reload()
        both(a, "T5 forge: a policy file the service never wrote, service restarted")
        print("\nverify() on the service's read path ->", a.verify(), a.verify_detail or "(served without complaint)")
    finally:
        a.teardown()


if __name__ == "__main__":
    main()
