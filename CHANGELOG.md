# Changelog

## 0.2.0 (2026-10-27)

- Second row: nonrtric-a1pms-filestore, the O-RAN SC non-RT RIC A1 Policy
  Management Service 2.13.0 with its file store, measured against two O-RAN
  SC A1 simulators. All ten edits accepted on the service's read path after
  a restart. The walkthrough also records the near-RT RIC's view: a file
  edit, a file deletion and a forged file each became the live A1 policy
  state on the RIC after the restart (results/a1pms-walkthrough.txt,
  results/a1sim-ric1-log-excerpt.txt).
- deploy/a1pms: docker-compose, A1PMS configuration, the policy type file
  and a restart script that waits for both RICs to be AVAILABLE.
- `requests` added as a dependency.

## 0.1.0 (2026-10-27)

- First row: oran-sc-sdl, the O-RAN SC near-RT RIC Shared Data Layer via
  ricsdl 3.1.2 on Redis 7, all ten agmi at-rest edits accepted on the read
  path.
- Runner `ricproof` with `--target` and `--json`; `experiments/
  sdl_walkthrough.py` repeats the edits outside the harness.
- Tests pin the measured verdicts, the adapter lifecycle, the T6 byte
  landing, the loss-versus-refusal rule in verify(), and the ricsdl
  get()/remove() str behaviour.
- The next stores (A1PMS file store, AIMLFW model store) are documented in
  docs/rows.md with their code facts; they get a row only when measured.
