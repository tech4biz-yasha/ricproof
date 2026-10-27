# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""O-RAN SC near-RT RIC Shared Data Layer (SDL), Python client ricsdl, on Redis.

What the store is
    The SDL is the near-RT RIC platform's shared state store. xApps and
    platform components (E2 Manager, Subscription Manager, the xApp
    framework) read and write it through the SDL client libraries, sdlgo and
    sdlpy (PyPI package ricsdl). The backing store is Redis (the RIC "dbaas"
    deployment). Both clients write the same key layout, so an edit made
    beneath sdlpy is an edit beneath sdlgo too.

Key layout, taken from ricsdl 3.1.2, ricsdl/backend/redis.py, line 422:
    '{' + ns + '},' + key
    One Redis string per SDL key, the SDL namespace in braces as the Redis
    hash tag. Values are the raw bytes the caller passed to set().

What one record is
    One SDL key inside one namespace. This adapter models what an xApp
    writing a decision log would write: keys rec-000000, rec-000001, ... in
    the xApp's own namespace, each value a small JSON document with the
    decision (content) and its bookkeeping (metadata: timestamp, source).
    The record ordering the edits need is the key order.

Two contexts
    Two SDL namespaces, standing for two xApps' namespaces. The owner of a
    record is the namespace it sits in, read from the Redis key itself,
    never from a field inside the value.

Where the attacker stands
    Write access to the Redis instance behind the SDL (store access), with no
    access to the xApp process. That is a compromised dbaas pod, a leaked
    Redis password, or any operator with redis-cli on the RIC cluster.

The read path, and what is measured
    verify() is the SDL client's own read path: find_keys() then get() on
    the namespace, exactly as an xApp reads its state back. The SDL exposes
    no integrity call, so the only way it can refuse an edit is on this
    read. detection_point is therefore "read". If get() returns the edited
    bytes without an error, the cell is accepted. The adapter never inspects
    the values itself.

Pinned
    ricsdl 3.1.2 (PyPI), the Redis server version is read from the server
    at measure time and printed in the row. Connection from
    RICPROOF_REDIS_URI, for example redis://localhost:6390. Each run uses
    its own namespaces under a random prefix and removes them on teardown.
"""

from __future__ import annotations

import json
import os
import secrets
from urllib.parse import urlparse

from agmi.adapters.base import MemoryAdapter, Record

CONTENT_KEYS = ("action", "marker")
META_KEYS = ("ts", "src")


def redis_uri() -> str | None:
    return os.environ.get("RICPROOF_REDIS_URI")


def _configure_ricsdl(uri: str) -> None:
    """ricsdl reads DBAAS_SERVICE_HOST and DBAAS_SERVICE_PORT at
    SyncStorage() construction (ricsdl/configuration.py, lines 72 to 74).
    Set them from the URI before the client is built."""
    u = urlparse(uri)
    os.environ["DBAAS_SERVICE_HOST"] = u.hostname or "localhost"
    os.environ["DBAAS_SERVICE_PORT"] = str(u.port or 6379)


class OranScSdlAdapter(MemoryAdapter):
    name = "oran-sc-sdl"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = True
    detection_point = "read"

    def __init__(self, uri: str | None = None):
        self._uri = uri or redis_uri()
        self._prefix: str | None = None
        self._sdl = None
        self._r = None
        self._count = 0

    # --- namespaces ---------------------------------------------------------

    @property
    def ns(self) -> str:
        return f"{self._prefix}-xapp-a"

    @property
    def other_ns(self) -> str:
        return f"{self._prefix}-xapp-b"

    @staticmethod
    def _rkey(ns: str, name: str) -> str:
        # ricsdl/backend/redis.py line 422: '{' + ns + '},' + key
        return "{" + ns + "}," + name

    def measured_on(self) -> str:
        """Pinned client version plus the server version read at measure time."""
        import redis
        import ricsdl
        server = redis.Redis.from_url(self._uri).info("server")["redis_version"]
        return f"ricsdl {ricsdl.__version__} on Redis {server}"

    # --- lifecycle ----------------------------------------------------------

    def _open(self) -> None:
        from ricsdl import syncstorage
        _configure_ricsdl(self._uri)
        self._sdl = syncstorage.SyncStorage()

    def setup(self) -> None:
        if not self._uri:
            raise RuntimeError("RICPROOF_REDIS_URI is not set")
        import redis
        self._prefix = f"ricproof-{secrets.token_hex(4)}"
        self._count = 0
        self._r = redis.Redis.from_url(self._uri)
        self._open()

    def teardown(self) -> None:
        if self._sdl is not None:
            try:
                for ns in (self.ns, self.other_ns):
                    self._sdl.remove_all(ns)
                self._sdl.close()
            except Exception:  # noqa: BLE001
                pass
        if self._r is not None and self._prefix:
            keys = list(self._r.scan_iter("{" + self._prefix + "-*"))
            if keys:
                self._r.delete(*keys)
        self._sdl = None
        self._prefix = None

    # --- the xApp's own write path ------------------------------------------

    @staticmethod
    def _doc(ns: str, i: int, token: str) -> bytes:
        return json.dumps({
            "ts": f"2026-10-27T00:00:{i:02d}Z",
            "src": ns,
            "action": f"handover ue-{i} to cell-{(i % 3) + 1}",
            "marker": f"{token}{i}",
        }, sort_keys=True).encode()

    def _seed_ns(self, ns: str, token: str, start: int, n: int) -> None:
        self._sdl.set(ns, {f"rec-{start + i:06d}": self._doc(ns, start + i, token)
                           for i in range(n)})

    def seed(self, n: int) -> None:
        self._seed_ns(self.ns, "sdl-seed-", 0, n)
        self._count = n

    def seed_other(self, n: int) -> None:
        self._seed_ns(self.other_ns, "sdl-other-", 0, n)

    def append_genuine(self) -> None:
        self._seed_ns(self.ns, "sdl-seed-", self._count, 1)
        self._count += 1

    def erase_genuine(self) -> list[str]:
        names = self._names(self.ns)
        victim = names[len(names) // 2]
        # ricsdl 3.1.2 syncstorage.py line 177 does list(keys): a bare str
        # becomes a list of characters and the intended key is not deleted,
        # so the key is passed as a one-element set.
        self._sdl.remove(self.ns, {victim})          # the SDL's own delete call
        return [self._rkey(self.ns, victim)]

    # --- raw access beneath the SDL -----------------------------------------

    def _names(self, ns: str) -> list[str]:
        pat = "{" + ns + "},rec-*"
        prefix_len = len("{" + ns + "},")
        return sorted(k.decode()[prefix_len:] for k in self._r.scan_iter(pat))

    def _read_ns(self, ns: str) -> list[Record]:
        out = []
        for i, name in enumerate(self._names(ns)):
            raw = self._r.get(self._rkey(ns, name))
            out.append(Record(seq=i, fields={
                "key": self._rkey(ns, name), "ns": ns, "name": name,
                "value": json.loads(raw)}))
        return out

    def read_all_raw(self) -> list[Record]:
        return self._read_ns(self.ns)

    def read_other_raw(self) -> list[Record]:
        return self._read_ns(self.other_ns)

    @staticmethod
    def _encode(value: dict) -> bytes:
        return json.dumps(value, sort_keys=True).encode()

    def write_raw(self, record: Record) -> None:
        names = self._names(self.ns)
        if record.seq < len(names):
            self._r.set(self._rkey(self.ns, names[record.seq]), self._encode(record.fields["value"]))
        else:
            self._r.set(self._rkey(self.ns, record.fields["name"]), self._encode(record.fields["value"]))

    def delete_raw(self, seq: int) -> None:
        names = self._names(self.ns)
        if seq >= len(names):
            raise IndexError(seq)
        self._r.delete(self._rkey(self.ns, names[seq]))

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        # the donor's exact bytes, into the victim's slot
        donor_bytes = self._r.get(donor.fields["key"])
        self._r.set(self._rkey(self.ns, self._names(self.ns)[victim_seq]), donor_bytes)

    def mutate_payload(self, record: Record) -> Record:
        value = json.loads(json.dumps(record.fields["value"]))
        value["action"] = value["action"].replace("handover", "release")
        value["marker"] = value["marker"].replace("sdl-seed-", "sdl-TAMP-")
        record.fields["value"] = value
        return record

    def forge_record(self, template: Record) -> Record:
        names = self._names(self.ns)
        nxt = int(names[-1].split("-")[1]) + 1
        value = json.loads(json.dumps(template.fields["value"]))
        value["action"] = f"handover ue-{nxt} to cell-9"
        value["marker"] = f"sdl-FORGED-{nxt}"
        return Record(seq=template.seq + 1, fields={
            "key": self._rkey(self.ns, f"rec-{nxt:06d}"), "ns": self.ns,
            "name": f"rec-{nxt:06d}", "value": value})

    # --- metadata (T8) --------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        """Everything in the value that is not content: ts, src and any
        key an edit added."""
        value = self.read_all_raw()[seq].fields["value"]
        return {k: v for k, v in value.items() if k not in CONTENT_KEYS}

    def write_meta(self, seq: int, meta: dict) -> None:
        """Replace the non-content keys with `meta` verbatim, content untouched."""
        name = self._names(self.ns)[seq]
        value = json.loads(self._r.get(self._rkey(self.ns, name)))
        value = {k: v for k, v in value.items() if k in CONTENT_KEYS}
        value.update(meta)
        self._r.set(self._rkey(self.ns, name), self._encode(value))

    # --- identity, payload, owner ---------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields["key"]

    def payload_of(self, record: Record) -> str:
        value = record.fields["value"]
        return json.dumps({k: value.get(k) for k in CONTENT_KEYS}, sort_keys=True)

    def owner_of(self, record: Record) -> str | None:
        # from the Redis key's hash tag, not from any field inside the value
        key = record.fields["key"]
        return key[1:key.index("},")]

    # --- whole-store rollback (T9, T10) ----------------------------------------

    def snapshot_store(self):
        snap = {}
        for ns in (self.ns, self.other_ns):
            for name in self._names(ns):
                k = self._rkey(ns, name)
                snap[k] = self._r.dump(k)
        return snap

    def restore_store(self, token) -> None:
        for ns in (self.ns, self.other_ns):
            keys = [self._rkey(ns, n) for n in self._names(ns)]
            if keys:
                self._r.delete(*keys)
        for k, dumped in token.items():
            self._r.restore(k, 0, dumped, replace=True)

    # --- the read path ----------------------------------------------------------

    def reload(self) -> None:
        try:
            self._sdl.close()
        except Exception:  # noqa: BLE001
            pass
        self._open()

    def verify(self) -> bool:
        """The SDL client's own read path: find_keys() then get(). True means
        the client served the namespace's records without complaint. False
        with verify_detail means it raised, or served nothing, or served
        fewer keys than it listed; the detail says which, so a loss is never
        read as a refusal. The adapter never looks at the values."""
        self.verify_detail = None
        try:
            keys = self._sdl.find_keys(self.ns, "rec-*")
            if not keys:
                self.verify_detail = "find_keys() listed no records (a loss, not a refusal)"
                return False
            served = self._sdl.get(self.ns, set(keys))
            missing = sorted(set(keys) - set(served))
            if missing:
                self.verify_detail = (f"get() served {len(served)} of {len(keys)} listed keys, "
                                      f"missing {missing[:3]} (a loss, not a refusal)")
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
