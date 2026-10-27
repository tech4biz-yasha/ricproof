# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pinned verdicts for the nonrtric-a1pms-filestore row and its lifecycle.

Needs a running A1PMS with two RICs and the RICPROOF_A1PMS_* variables
(see deploy/a1pms); skipped otherwise. Each restart takes about 25 s, so
the full pinned run is several minutes.
"""

from __future__ import annotations

import os

import pytest

from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE
from agmi.runner import run_matrix

from ricproof.adapters.nonrtric_a1pms import NonRtRicA1PmsFileStoreAdapter

READY = all(os.environ.get(v) for v in ("RICPROOF_A1PMS_URL", "RICPROOF_A1PMS_VARDATA", "RICPROOF_A1PMS_RESTART_CMD"))
pytestmark = pytest.mark.skipif(not READY, reason="RICPROOF_A1PMS_* not set")

EXPECTED = {name: "VULNERABLE" for name in (
    "tamper", "truncate", "delete_middle", "reorder", "forge", "cross_replay",
    "rollback_replay", "metadata_tamper", "snapshot_rollback", "erase_resurrect")}


def test_lifecycle_seed_read_edit_delete():
    a = NonRtRicA1PmsFileStoreAdapter()
    a.setup()
    try:
        a.seed(3)
        recs = a.read_all_raw()
        assert [r.fields["doc"]["id"] for r in recs] == ["rp-000000", "rp-000001", "rp-000002"]
        assert a.owner_of(recs[0]) == a.ric
        assert a.identity_of(recs[0]).endswith("/rp-000000.json")
        assert a.verify() is True
        a.seed_other(2)
        others = a.read_other_raw()
        assert a.owner_of(others[0]) == a.other_ric
        assert a.payload_of(others[0]) != a.payload_of(recs[0])
        a.delete_raw(2)
        assert len(a.read_all_raw()) == 2
        with pytest.raises(IndexError):
            a.delete_raw(9)
    finally:
        a.teardown()


def test_pinned_verdicts():
    attacks = [cls() for cls in AT_REST_ATTACKS_WITH_ERASE]
    results = run_matrix([NonRtRicA1PmsFileStoreAdapter()], attacks)
    got = {r.attack: r.status for r in results}
    assert got == EXPECTED, {k: (got.get(k), r.guard or r.error) for k in EXPECTED
                              for r in results if r.attack == k}
