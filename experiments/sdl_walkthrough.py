# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Independent walkthrough of the oran-sc-sdl row, outside the agmi harness.

Each step makes one edit beneath the SDL client and prints what the client
then returns on its own read path, so the scorecard's "accepted" cells can
be checked by eye. Needs RICPROOF_REDIS_URI.

    python experiments/sdl_walkthrough.py
"""

from __future__ import annotations

import json

from ricproof.adapters.oran_sc_sdl import OranScSdlAdapter


def show(a: OranScSdlAdapter, label: str) -> None:
    keys = sorted(a._sdl.find_keys(a.ns, "rec-*"))
    got = a._sdl.get(a.ns, set(keys)) if keys else {}
    print(f"\n[{label}] client lists {len(keys)} key(s):")
    for k in keys:
        v = json.loads(got[k])
        print(f"  {k}: marker={v.get('marker')} src={v.get('src', '')[-6:]} "
              f"extra={[x for x in v if x not in ('ts', 'src', 'action', 'marker')]}")


def main() -> None:
    a = OranScSdlAdapter()
    a.setup()
    try:
        a.seed(5)
        show(a, "T0 seeded through SDL set()")

        rec = a.read_all_raw()[2]
        a.write_raw(a.mutate_payload(rec))
        show(a, "T1 tamper: rec-000002 content rewritten beneath the client")

        a.delete_raw(4)
        show(a, "T2 truncate: newest key deleted beneath the client")

        a.seed_other(5)
        a.replay_onto(3, a.read_other_raw()[-1])
        show(a, "T6 cross-context replay: other xApp's record bytes placed in rec-000003 (src shows the other namespace)")

        meta = a.read_meta(1)
        meta["ricproof_meta_tampered"] = True
        a.write_meta(1, meta)
        show(a, "T8 metadata: extra bookkeeping field added to rec-000001, content untouched")

        token = a.snapshot_store()
        a.append_genuine()
        show(a, "T9 step 1: one more genuine record appended through SDL set()")
        a.restore_store(token)
        show(a, "T9 step 2: older copy restored; the newest genuine record is gone")

        token = a.snapshot_store()
        erased = a.erase_genuine()
        show(a, f"T10 step 1: SDL remove() erased {erased[0].split(',')[-1]}")
        a.restore_store(token)
        show(a, "T10 step 2: pre-erasure copy restored; the erased record is served again")

        a.reload()
        print("\nreload(): client reopened; verify() ->", a.verify(), a.verify_detail or "(served without complaint)")
    finally:
        a.teardown()


if __name__ == "__main__":
    main()
