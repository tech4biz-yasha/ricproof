# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""O-RAN SC non-RT RIC A1 Policy Management Service (A1PMS), file store.

What the store is
    A1PMS is the non-RT RIC component that holds the A1 policies rApps and
    operators create and pushes them to the near-RT RICs over A1. The O-RAN
    SC image (nonrtric-plt-a1policymanagementservice 2.13.0) runs ONAP
    CCSDK's a1-policy-management; the persisted store is the file store,
    used when neither Postgres nor S3 is configured (the image default).

On-disk layout, from ccsdk-oran FileStore.java and Policies.java
    <vardata-directory>/database/policies/<ricId>/<policyId>.json
    One JSON document per policy: id, json (the policy body as a string),
    ownerServiceId, ricId, typeId, statusNotificationUri, isTransient,
    lastModified. Written by FileStore.writeObject (a FileOutputStream),
    read by FileStore.readObject (Files.readAllBytes). No digest, signature
    or chain in that file.

What one record is
    One policy file. Content is the policy body (the "json" field: what the
    near-RT RIC enforces). Metadata is ownerServiceId, statusNotificationUri,
    isTransient and lastModified. The id and the ricId are the record's
    identity and location and stay with the slot. Record order is policy-id
    order.

Two contexts
    Two near-RT RICs (ric1 and ric2), each its own directory under policies/.
    A record's owner is the directory it sits in, never a field inside it.

Where the attacker stands
    Write access to the vardata directory (a mounted volume, a node with the
    pod's filesystem, a backup). No access to the running service.

The read path, and what is measured
    A1PMS keeps policies in memory while it runs, so an on-disk edit is
    invisible until a restart. reload() restarts the service; at startup
    Policies.restoreFromDatabase reads the files back and
    RicSynchronizationTask.recreateAllPoliciesInRic then PUTs every stored
    policy to its near-RT RIC (ccsdk-oran RicSynchronizationTask.java lines
    185 to 189). verify() is the service's own REST read path after that:
    GET /a1-policy/v2/policies?ric_id=ric1 then GET /a1-policy/v2/policies/{id}
    for each id it lists. True means it served them without complaint.
    detection_point is "read". The near-RT RIC's own view after the edit is
    recorded by experiments/a1pms_walkthrough.py, not by this cell.

Environment
    RICPROOF_A1PMS_URL          e.g. http://localhost:8081
    RICPROOF_A1PMS_VARDATA      the service's vardata directory (host path of
                                the mounted volume on Docker)
    RICPROOF_A1PMS_RESTART_CMD  shell command that restarts the service and
                                returns once both RICs are AVAILABLE
    RICPROOF_A1PMS_STOP_CMD     optional shell command that stops it (used
                                before a whole-store restore); default: none
    RICPROOF_A1PMS_RICS         optional "ric1,ric2" (default)
    RICPROOF_A1PMS_TYPE         optional policy type id (default "1")

Pinned
    nonrtric-plt-a1policymanagementservice 2.13.0 (Implementation-Version in
    the jar manifest), measured against two O-RAN SC A1 simulators
    (sim-a1-interface, OSC_2.1.0).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

META_KEYS = ("ownerServiceId", "statusNotificationUri", "isTransient", "lastModified")
IDENTITY_KEYS = ("id", "ricId")
NA_REASON = ("A1PMS row needs RICPROOF_A1PMS_URL, RICPROOF_A1PMS_VARDATA and "
             "RICPROOF_A1PMS_RESTART_CMD against a running A1PMS")


class NonRtRicA1PmsFileStoreAdapter(MemoryAdapter):
    name = "nonrtric-a1pms-filestore"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = True
    detection_point = "read"

    def __init__(self):
        self._url = os.environ.get("RICPROOF_A1PMS_URL", "").rstrip("/")
        self._vardata = os.environ.get("RICPROOF_A1PMS_VARDATA")
        self._restart = os.environ.get("RICPROOF_A1PMS_RESTART_CMD")
        self._stop = os.environ.get("RICPROOF_A1PMS_STOP_CMD")
        rics = os.environ.get("RICPROOF_A1PMS_RICS", "ric1,ric2").split(",")
        self.ric, self.other_ric = rics[0].strip(), rics[1].strip()
        self._type = os.environ.get("RICPROOF_A1PMS_TYPE", "1")
        self._count = 0

    # --- service access -----------------------------------------------------

    def _http(self):
        import requests
        return requests

    def measured_on(self) -> str:
        return "nonrtric-plt-a1policymanagementservice 2.13.0 (file store) with two OSC_2.1.0 A1 simulators"

    def _dir(self, ric: str) -> Path:
        return Path(self._vardata) / "database" / "policies" / ric

    def _run(self, cmd: str) -> None:
        subprocess.run(cmd, shell=True, check=True, timeout=300)

    # --- lifecycle ------------------------------------------------------------

    def setup(self) -> None:
        if not (self._url and self._vardata and self._restart):
            raise RuntimeError(NA_REASON)
        self._count = 0
        # a fresh store: delete every policy of both RICs through the service's own API
        r = self._http()
        for ric in (self.ric, self.other_ric):
            ids = r.get(f"{self._url}/a1-policy/v2/policies", params={"ric_id": ric}, timeout=30).json()["policy_ids"]
            for pid in ids:
                r.delete(f"{self._url}/a1-policy/v2/policies/{pid}", timeout=30)
        for ric in (self.ric, self.other_ric):
            d = self._dir(ric)
            if d.exists():
                for f in d.glob("*.json"):
                    f.unlink()

    def teardown(self) -> None:
        try:
            self.setup()
        except Exception:  # noqa: BLE001
            pass

    # --- the service's own write path -----------------------------------------

    def _put(self, ric: str, pid: str, i: int, token: str) -> None:
        body = {"ric_id": ric, "policy_id": pid, "service_id": "ricproof", "policytype_id": self._type,
                "policy_data": {"scope": {"ueId": f"{token}{i}", "qosId": f"qos{i}"},
                                "statement": {"priorityLevel": i + 1}}}
        resp = self._http().put(f"{self._url}/a1-policy/v2/policies", json=body, timeout=30)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"PUT policy {pid} -> {resp.status_code} {resp.text[:120]}")

    def seed(self, n: int) -> None:
        for i in range(n):
            self._put(self.ric, f"rp-{i:06d}", i, "ue-seed-")
        self._count = n

    def seed_other(self, n: int) -> None:
        for i in range(n):
            self._put(self.other_ric, f"rq-{i:06d}", i, "ue-other-")

    def append_genuine(self) -> None:
        self._put(self.ric, f"rp-{self._count:06d}", self._count, "ue-seed-")
        self._count += 1

    def erase_genuine(self) -> list[str]:
        files = self._files(self.ric)
        victim = files[len(files) // 2]
        resp = self._http().delete(f"{self._url}/a1-policy/v2/policies/{victim.stem}", timeout=30)
        if resp.status_code not in (200, 204):
            raise RuntimeError(f"DELETE {victim.stem} -> {resp.status_code}")
        return [str(victim)]

    # --- raw access beneath the service -------------------------------------

    def _files(self, ric: str) -> list[Path]:
        d = self._dir(ric)
        return sorted(d.glob("*.json")) if d.exists() else []

    def _read_ric(self, ric: str) -> list[Record]:
        out = []
        for i, f in enumerate(self._files(ric)):
            out.append(Record(seq=i, fields={"path": str(f), "ric": ric, "doc": json.loads(f.read_text())}))
        return out

    def read_all_raw(self) -> list[Record]:
        return self._read_ric(self.ric)

    def read_other_raw(self) -> list[Record]:
        return self._read_ric(self.other_ric)

    def _write_into_slot(self, path: Path, donor_doc: dict) -> None:
        """Keep the slot's identity (id, ricId), take everything else from the donor."""
        cur = json.loads(path.read_text())
        new = dict(donor_doc)
        for k in IDENTITY_KEYS:
            new[k] = cur[k]
        path.write_text(json.dumps(new))

    def write_raw(self, record: Record) -> None:
        files = self._files(self.ric)
        if record.seq < len(files):
            self._write_into_slot(files[record.seq], record.fields["doc"])
        else:
            doc = record.fields["doc"]
            (self._dir(self.ric) / f"{doc['id']}.json").write_text(json.dumps(doc))

    def delete_raw(self, seq: int) -> None:
        files = self._files(self.ric)
        if seq >= len(files):
            raise IndexError(seq)
        files[seq].unlink()

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        self._write_into_slot(self._files(self.ric)[victim_seq], donor.fields["doc"])

    def mutate_payload(self, record: Record) -> Record:
        doc = json.loads(json.dumps(record.fields["doc"]))
        body = json.loads(doc["json"])
        body["statement"]["priorityLevel"] = 99
        body["scope"]["ueId"] = body["scope"]["ueId"].replace("ue-seed-", "ue-TAMP-")
        doc["json"] = json.dumps(body)
        record.fields["doc"] = doc
        return record

    def forge_record(self, template: Record) -> Record:
        files = self._files(self.ric)
        nxt = int(files[-1].stem.split("-")[1]) + 1
        doc = json.loads(json.dumps(template.fields["doc"]))
        doc["id"] = f"rp-{nxt:06d}"
        body = json.loads(doc["json"])
        body["scope"]["ueId"] = f"ue-FORGED-{nxt}"
        body["statement"]["priorityLevel"] = 77
        doc["json"] = json.dumps(body)
        return Record(seq=template.seq + 1, fields={"path": str(self._dir(self.ric) / f"{doc['id']}.json"),
                                                    "ric": self.ric, "doc": doc})

    # --- metadata (T8) ----------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        doc = self.read_all_raw()[seq].fields["doc"]
        return {k: v for k, v in doc.items() if k not in ("json",) + IDENTITY_KEYS + ("typeId",)}

    def write_meta(self, seq: int, meta: dict) -> None:
        path = self._files(self.ric)[seq]
        doc = json.loads(path.read_text())
        doc = {k: v for k, v in doc.items() if k in ("json",) + IDENTITY_KEYS + ("typeId",)}
        doc.update(meta)
        path.write_text(json.dumps(doc))

    # --- identity, payload, owner ---------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields["path"]

    def payload_of(self, record: Record) -> str:
        return json.dumps(json.loads(record.fields["doc"]["json"]), sort_keys=True)

    def owner_of(self, record: Record) -> str | None:
        return Path(record.fields["path"]).parent.name

    # --- whole-store rollback (T9, T10) ---------------------------------------

    def snapshot_store(self):
        src = Path(self._vardata) / "database"
        dst = Path(tempfile.mkdtemp(prefix="ricproof-a1pms-")) / "database"
        shutil.copytree(src, dst)
        return str(dst)

    def restore_store(self, token) -> None:
        if self._stop:
            self._run(self._stop)
        dst = Path(self._vardata) / "database"
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(token, dst)

    # --- the read path ----------------------------------------------------------

    def reload(self) -> None:
        self._run(self._restart)

    def verify(self) -> bool:
        self.verify_detail = None
        r = self._http()
        try:
            listed = r.get(f"{self._url}/a1-policy/v2/policies", params={"ric_id": self.ric}, timeout=30)
            if listed.status_code != 200:
                self.verify_detail = f"list -> HTTP {listed.status_code}: {listed.text[:120]}"
                return False
            ids = listed.json()["policy_ids"]
            if not ids:
                self.verify_detail = "the service lists no policies for the RIC (a loss, not a refusal)"
                return False
            for pid in ids:
                one = r.get(f"{self._url}/a1-policy/v2/policies/{pid}", timeout=30)
                if one.status_code != 200:
                    self.verify_detail = f"GET {pid} -> HTTP {one.status_code}: {one.text[:120]}"
                    return False
            return True
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
