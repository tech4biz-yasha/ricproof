# Rows

## oran-sc-sdl (measured)

See the README section "The oran-sc-sdl row" and the adapter docstring in
`ricproof/adapters/oran_sc_sdl.py`. Pinned: ricsdl 3.1.2, Redis server
version read at measure time. Results in `results/scorecard.json`.

## nonrtric-a1pms-filestore (measured)

See the README section "The nonrtric-a1pms-filestore row" and the adapter
docstring in `ricproof/adapters/nonrtric_a1pms.py`. Measured 27 Oct 2026
with Docker: the O-RAN SC image 2.13.0 (jar sha256 3dd11f31…cb5f) and two
o-ran-sc/a1-simulator 2.8.1 containers (OSC_2.1.0), started from
deploy/a1pms. First measured the same day on the image's layers run
directly on Java 21, with the same ten verdicts.

Running it with Docker (deploy/a1pms):

1. `cd deploy/a1pms && mkdir -p vardata && docker compose up -d`
2. Give each simulator the policy type:
   `curl -X PUT -H 'Content-Type: application/json' --data-binary @policy-type-1.json http://localhost:8085/a1-p/policytypes/1`
   and the same against `http://localhost:8086/a1-p/policytypes/1`.
3. Wait until `curl http://localhost:8081/a1-policy/v2/rics` shows both RICs
   `"state":"AVAILABLE"` with `"policytype_ids":["1"]`. If it shows
   `"policytype_ids":[]`, the types were created after the service started:
   run `./a1pms-ctl.sh restart` and check again.
4. Export the RICPROOF_A1PMS_* variables as in the README and run the row.

The vardata directory on the host is the service's file store; the
container runs as uid 120957, so the directory must be writable by it
(it was on Docker Desktop for Mac in the measured run).

## aimlfw-mme-s3 (next; code facts checked, no adapter yet)

Store: AIMLFW Model Management Service (Go) with an S3-compatible bucket.
Artefacts `<name>_model.zip`, info `<name>_info.json` (config.env), model
information rows in a GORM database.

Code facts (commit 84f4f88, 21 Oct 2026): `core/s3_manager.go
GetBucketObject()` is `s3.GetObject` plus `io.ReadAll`; the non-test Go
sources contain no occurrence of sha256, sha1, md5, checksum, digest,
signature, hmac or integrity. An observation about the code, not a
verdict.

How to measure: deploy AIMLFW per its installation guide
(docs.o-ran-sc.org, aimlfw-dep), register and upload a model, then write
the adapter: seed = register and upload through the MME API; raw edits =
objects in the bucket and rows in the database; verify = the MME's model
download and discovery endpoints.

## Planned

- flexric-xapp-sqlite: the FlexRIC xApp SDK's SQLite sink for indications.
  Needs FlexRIC built from source; the sink has no read path of its own, so
  the row's detection point and n/a reasons must be stated from the code
  before a cell is published.
- e2-control-applied: an E2 RIC Control acknowledged by the near-RT RIC
  versus the parameter actually in force at the gNB. srsRAN Project gNB
  over ZMQ first, then OpenAirInterface. Not an at-rest edit; a new attack
  class in ricproof, with its own landed check.
