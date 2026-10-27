# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pinned verdicts for the oran-sc-sdl row and the adapter's own lifecycle.

Needs a Redis reachable at RICPROOF_REDIS_URI; skipped otherwise. The
expected cells are what ricsdl 3.1.2 on Redis 7 measured on 27 Oct 2026:
every edit accepted on the read path. If a ricsdl or RIC release starts
refusing an edit, this test fails and the row is re-measured on purpose.
"""

from __future__ import annotations

import os

import pytest
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE
from agmi.runner import run_matrix

from ricproof.adapters.oran_sc_sdl import OranScSdlAdapter

URI = os.environ.get("RICPROOF_REDIS_URI")
pytestmark = pytest.mark.skipif(not URI, reason="RICPROOF_REDIS_URI not set")

EXPECTED = {
    "tamper": "VULNERABLE", "truncate": "VULNERABLE", "delete_middle": "VULNERABLE",
    "reorder": "VULNERABLE", "forge": "VULNERABLE", "cross_replay": "VULNERABLE",
    "rollback_replay": "VULNERABLE", "metadata_tamper": "VULNERABLE",
    "snapshot_rollback": "VULNERABLE", "erase_resurrect": "VULNERABLE",
}


def test_lifecycle_seed_read_edit_delete():
    a = OranScSdlAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        assert [r.fields["name"] for r in recs] == [f"rec-{i:06d}" for i in range(5)]
        assert a.owner_of(recs[0]) == a.ns
        assert a.identity_of(recs[0]) == "{" + a.ns + "},rec-000000"
        assert a.verify() is True
        a.seed_other(5)
        others = a.read_other_raw()
        assert a.owner_of(others[0]) == a.other_ns
        assert a.payload_of(others[0]) != a.payload_of(recs[0])
        a.delete_raw(4)
        assert len(a.read_all_raw()) == 4
        with pytest.raises(IndexError):
            a.delete_raw(9)
        a.reload()
        assert a.verify() is True
    finally:
        a.teardown()
    # teardown removed every key under the run's prefix
    import redis
    assert not list(redis.Redis.from_url(URI).scan_iter("{" + str(a._prefix) + "-*"))


def test_sdl_get_and_remove_need_a_set_not_a_str():
    """ricsdl 3.1.2 syncstorage.py lines 164 and 177: get() and remove()
    both do list(keys), so a bare str is split into characters; get()
    returns an empty dict and remove() deletes nothing intended. The adapter
    passes sets; this pins the behaviour the comments rely on."""
    a = OranScSdlAdapter()
    a.setup()
    try:
        a.seed(3)
        assert a._sdl.get(a.ns, "rec-000001") == {}
        assert set(a._sdl.get(a.ns, {"rec-000001"})) == {"rec-000001"}
        a._sdl.remove(a.ns, "rec-000001")
        assert len(a.read_all_raw()) == 3        # nothing intended was deleted
        a._sdl.remove(a.ns, {"rec-000001"})
        assert len(a.read_all_raw()) == 2
    finally:
        a.teardown()


def test_verify_reports_a_loss_as_a_loss():
    """If every record is gone beneath the client, verify() must say so in
    its detail rather than returning True (served) or a bare False (refused)."""
    a = OranScSdlAdapter()
    a.setup()
    try:
        a.seed(2)
        assert a.verify() is True
        for seq in (1, 0):
            a.delete_raw(seq)
        assert a.verify() is False
        assert "loss" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_t6_lands_the_donor_bytes_exactly():
    a = OranScSdlAdapter()
    a.setup()
    try:
        a.seed(3)
        a.seed_other(3)
        donor = a.read_other_raw()[-1]
        a.replay_onto(2, donor)
        victim = a.read_all_raw()[2]
        assert a._r.get(victim.fields["key"]) == a._r.get(donor.fields["key"])
        assert a.owner_of(victim) == a.ns and a.owner_of(donor) == a.other_ns
        assert a.payload_of(victim) == a.payload_of(donor)
    finally:
        a.teardown()


def test_pinned_verdicts():
    attacks = [cls() for cls in AT_REST_ATTACKS_WITH_ERASE]
    results = run_matrix([OranScSdlAdapter()], attacks)
    got = {r.attack: r.status for r in results}
    assert got == EXPECTED, {k: (got.get(k), r.guard or r.error) for k in EXPECTED
                              for r in results if r.attack == k}
