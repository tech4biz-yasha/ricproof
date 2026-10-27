# ricproof

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23696820.svg)](https://doi.org/10.5281/zenodo.23696820)

Does an Open RAN RIC notice when its stores are tampered with?

ricproof runs the ten agmi at-rest edits (T1 to T10) unchanged against the
stores a RAN Intelligent Controller keeps its state, policies and models
in. Each row is one real store, driven through its own client library or
API: the edits are made beneath that API, and the verdict is the store's
own answer on its read path. The method, the landed-edit guard (control C3)
and the verdict words are the ones defined for
[agmi](https://github.com/tech4biz-yasha/agent-memory-integrity) and
draft-khandelwal-bmwg-agent-memory-integrity, so a ricproof cell means the
same thing as an agmi cell.

Status: 0.2.0, two measured rows (27 Oct 2026). Only measured stores get a
row; the next stores, with the code facts already checked for them, are in
docs/rows.md.

## Scorecard

Verdict words: **rejected** (the store refused the edit on its read path),
**reported** (its separate audit call named it), **accepted** (it served
the edit as genuine), **n/a** (not measured, reason in the cell), **error**
(the edit did not land as intended; the harness is at fault, not the store).

| row | measured on | T1 tamper | T2 truncate | T3 delete middle | T4 reorder | T5 forge | T6 cross-context replay | T7 rollback replay | T8 metadata | T9 snapshot rollback | T10 erase resurrect |
|---|---|---|---|---|---|---|---|---|---|---|---|
| oran-sc-sdl | ricsdl 3.1.2 on Redis 7.4.12, detection point read | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |
| nonrtric-a1pms-filestore | nonrtric-plt-a1policymanagementservice 2.13.0 (file store) with two OSC_2.1.0 A1 simulators, detection point read | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |

The table is generated from `results/scorecard.json`, which is written by
`ricproof --json results/scorecard.json`. Every cell in it carries the
attack version and the guard's reason when an edit did not land.

## The oran-sc-sdl row

What is measured. The O-RAN SC near-RT RIC Shared Data Layer, the state
store xApps and platform components read and write through the SDL client
libraries. The row drives the Python client, ricsdl 3.1.2 from PyPI,
against a Redis 7 server.

Key layout. One Redis string per SDL key, named `{<namespace>},<key>`.
This is ricsdl 3.1.2, `ricsdl/backend/redis.py` line 422, and the Go
client writes the same prefix: ric-plt-sdlgo `sdl.go` line 69
(`nsPrefix: "{" + NameSpace + "},"`, commit 6d4fa2e, 21 Oct 2026). An edit
beneath the Python client is therefore the same edit beneath the Go client.

Record model. Keys `rec-000000` onward in an xApp's namespace, each a JSON
value with a decision (`action`, `marker`: the content) and bookkeeping
(`ts`, `src`: the metadata). A second namespace stands for a second xApp.
A record's owner is the namespace in its Redis key, never a field inside
the value.

Attacker. Write access to the Redis instance behind the SDL, no access to
the xApp process.

Read path. `find_keys()` then `get()` on the namespace, as an xApp reads its
state back. The SDL has no integrity call, so this read is the only place
it could refuse an edit; the detection point is `read`.

Result. All ten edits are served without an error. The SDL client returns
the edited, replayed, rolled-back or resurrected values as the stored
state. `experiments/sdl_walkthrough.py` makes the same edits outside the
harness and prints what the client lists and serves after each one.

What verify() counts as served. True only when `find_keys()` lists records
and `get()` returns every listed key. A client that raises, lists nothing,
or serves fewer keys than it listed returns False with the reason in the
cell detail, so a loss is never printed as a refusal.

## The nonrtric-a1pms-filestore row

What is measured. The O-RAN SC non-RT RIC A1 Policy Management Service, the
component that holds the A1 policies rApps and operators create and pushes
them to the near-RT RICs. The row runs the real O-RAN SC image, tag 2.13.0
(policy-agent.jar sha256 3dd11f31…cb5f, Implementation-Version 2.13.0,
Spring Boot 4.1.0 in its manifest), with its file store, against two O-RAN
SC A1 simulator containers (o-ran-sc/a1-simulator 2.8.1, A1 version
OSC_2.1.0) standing in for two near-RT RICs, all three started from
deploy/a1pms/docker-compose.yml.

On-disk layout. `<vardata>/database/policies/<ricId>/<policyId>.json`, one
JSON document per policy (id, json, ownerServiceId, ricId, typeId,
statusNotificationUri, isTransient, lastModified), written with a
`FileOutputStream` and read with `Files.readAllBytes` (ONAP CCSDK
`FileStore.java`, commit 62191d4). No digest, signature or chain in that
file.

Record model. One policy file; content is the policy body (the `json`
field), metadata is ownerServiceId, statusNotificationUri, isTransient and
lastModified; id and ricId stay with the slot. The second context is the
second RIC's directory. Owner is the directory a file sits in.

Attacker. Write access to the vardata directory (a mounted volume, the
node's filesystem, a backup). No access to the running service.

Read path. A1PMS keeps policies in memory while running, so an on-disk edit
is invisible until a restart; `reload()` restarts the service. At startup
it reads the files back, and `RicSynchronizationTask.runSynchronization`
then deletes from each RIC every policy not in its store and PUTs every
stored policy to the RIC (`recreateAllPoliciesInRic`, ccsdk-oran
`RicSynchronizationTask.java` lines 185 to 189; the PUT at lines 172 to
174). `verify()` is the service's own REST read path after that: list the
RIC's policies, then GET each one. Detection point `read`.

Result. All ten edits accepted. `experiments/a1pms_walkthrough.py` repeats
three of them by hand and also reads the near-RT RIC's own view; its output
is in `results/a1pms-walkthrough.txt` and the matching simulator log lines
are in `results/a1sim-ric1-log-excerpt.txt`:

1. Tamper: priorityLevel 2 changed to 99 in the file. After the restart
   A1PMS serves 99, the simulator log shows A1PMS PUT the policy to the
   RIC again, and the RIC's own GET returns 99.
2. Truncate: the newest policy's file deleted. After the restart A1PMS lists
   two policies, the simulator log shows A1PMS sent DELETE for the third,
   and the RIC's own policy list no longer includes it.
3. Forge: a policy file the service never wrote. After the restart A1PMS
   serves it, the simulator log shows A1PMS PUT it to the RIC, and the
   RIC's own GET returns priorityLevel 77: a policy nobody created through
   the API is in force.

Measured statements above are tied to `results/scorecard.json`, the
walkthrough output and the log excerpt, all from one machine and one day.
The one explanatory statement, that the restart rebuilds the RIC from the
store, is bounded to the named function and lines in ccsdk-oran. The same
ten verdicts were first measured the same day on the image's own layers run
directly on Java 21, before the Docker run.

## Observations from the code (not verdicts)

These were read from the sources at the commits named. They say what the
code does; a verdict only comes from running the edits.

1. ricsdl 3.1.2 `syncstorage.py` lines 164 and 177: `get()` and `remove()`
   accept a `str` or a `Set[str]` by their type hints and both call
   `list(keys)`. A bare `str` is split into characters, so
   `remove(ns, "rec-000001")` deletes nothing intended. The adapter passes
   a one-element set; `tests/test_oran_sc_sdl.py` pins the behaviour.
2. aiml-fw-awmf-modelmgmtservice (commit 84f4f88, 21 Oct 2026):
   `core/s3_manager.go GetBucketObject()` is `s3.GetObject` plus
   `io.ReadAll`. The non-test Go sources contain no occurrence of sha256,
   sha1, md5, checksum, digest, signature, hmac or integrity.

## Next rows

In order, with what each needs, in docs/rows.md: the AIMLFW Model
Management Service model store (Kubernetes), the FlexRIC xApp SQLite sink,
and the control-action row (an E2 control acknowledged by the RIC versus
the parameter actually in force at the gNB) on srsRAN and OpenAirInterface.
None of these has a cell until it is measured.

## Run it

Needs Python 3.10 or newer and a Redis you can write to.

```
pip install "agent-memory-integrity @ git+https://github.com/tech4biz-yasha/agent-memory-integrity@e7fef1819e98b22345c94242bfa74e44afd3ff9c"
pip install redis==4.3.6
pip install ricsdl==3.1.2 --no-deps
pip install -e .
export RICPROOF_REDIS_URI=redis://localhost:6390
ricproof --target oran-sc-sdl --json results/scorecard.json
pytest -q
python experiments/sdl_walkthrough.py
```

The A1PMS row needs Docker. `deploy/a1pms/docker-compose.yml` starts two
A1 simulators and the A1PMS 2.13.0 image with its file store on
`deploy/a1pms/vardata`; docs/rows.md has the exact steps, including the
policy type each simulator needs before A1PMS can create policies. Then:

```
export RICPROOF_A1PMS_URL=http://localhost:8081
export RICPROOF_A1PMS_VARDATA=$PWD/deploy/a1pms/vardata
export RICPROOF_A1PMS_RESTART_CMD="$PWD/deploy/a1pms/a1pms-ctl.sh restart"
export RICPROOF_A1PMS_STOP_CMD="$PWD/deploy/a1pms/a1pms-ctl.sh stop"
export RICPROOF_A1SIM_URL=http://localhost:8085
ricproof --target nonrtric-a1pms-filestore --json results/scorecard.json
python experiments/a1pms_walkthrough.py
```

Each A1PMS restart takes about 25 seconds and the matrix restarts it
about twenty times, so the row takes around ten minutes.

ricsdl 3.1.2 pins hiredis 2.0.0, which does not build on Python 3.12;
installing ricsdl with `--no-deps` on top of redis 4.3.6 (the version it
pins) is the workaround. The runner uses its own namespaces under a random
`ricproof-` prefix and deletes them on teardown.

## Method

The edits, the guard and the verdict words are agmi's. The at-rest method
text is in draft-khandelwal-bmwg-agent-memory-integrity (IETF, individual
Internet-Draft). The pinned agmi commit is the one that carries T10.

## Author

Yasha Khandelwal, yasha.khandelwal@tech4biz.io. MIT licence.
