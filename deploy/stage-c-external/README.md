# Stage-C external live bridge

This directory documents the repository-shipped bridge for
`external-pending-buy`, `external-fill`, `external-protection-cancel`, and
`frozen-balance`. Repository presence is not deployment attestation: all four
scenarios remain `EXTERNAL OPEN` until a real Linux/IAM/OKX Demo/WORM run
passes the production loader.

## Per-run isolation

Choose a new opaque `RUN_ID` for every attempt. It is a filesystem/systemd
instance identifier, not the registrar-generated `challenge_id`. Never reuse
its directories. Before challenge issuance, start these `@RUN_ID` services so
the capability authority can capture their live `MainPID`, `InvocationID`,
cgroup, executable and role STS identity:

- fault driver: `okx-quant-stage-c-external-actor@RUN_ID`;
- challenge consumer: `okx-quant-stage-c-challenge-consumer@RUN_ID`;
- five acquirers: systemd, clock, provider, OKX, journal;
- five event signers: systemd, clock, provider, OKX, journal;
- parser/assembler: `okx-quant-stage-c-external-assembler@RUN_ID`;
- the independently hosted `provider_receipt_authority`.

Every role requires a distinct Unix identity, systemd invocation, STS session
and Ed25519 key. The capability must also bind the actor as `fault_driver`.
The provider receipt authority uses a separate key from both the local
`provider_acquirer` and local `provider` event signer.

The services initially wait without mutating OKX. The capability authority
then builds the capability, the registrar writes the challenge to
`challenges/RUN_ID.json`, and the challenge consumer performs the DynamoDB
conditional put. The actor will not mutate until the systemd acquirer has
sealed `driver.invoked`; it remains the same PID until `run.completed` has
been acquired.

## Evidence flow

1. Each acquirer signs every live acquisition envelope with its acquirer key.
2. Every event signer reads all five collections, independently verifies all
   acquirer proofs, derives the same global sequence, and signs only its role.
3. The parser workload verifies all fragments and emits `native-events.jsonl`.
4. `stage_c_chaos_producer.py produce` recomputes semantic facts from native
   bytes and creates the observation and drill receipt.
5. Raw collections, fragments, JSONL, observation, receipt, capability,
   challenge and consumption receipt are uploaded to Object Lock COMPLIANCE
   storage and independently read back by exact version.
6. Cleanup may begin after the final systemd raw cut exists. It must not delete
   any evidence and must still execute when signing or publishing fails.

The provider acquirer receives
`deploy/stage-c-external-provider.env.example` and a systemd credential
containing its bearer token. OKX acquirer credentials must be simulated,
read-only and bound by fingerprint/TLS certificate/SPKI in the challenge.

## External deployment attestation (P1-03/P1-04/P1-05)

After the run, an independent deployment verifier may sign one
`okx-quant.external-deployment-attestation/v1` payload.  The repository
validator is deliberately strict:

```bash
.venv/bin/python scripts/verify_external_deployment_attestation.py \
  --attestation /secure-transfer/external-deployment-attestation.json \
  --public-key /etc/okx-quant/stage-c/keys/deployment-verifier-public.pem \
  --expected-candidate-sha256 "$CANDIDATE_SHA256"
```

The payload must independently identify all three Demo accounts and all three
host/network/cgroup/credential failure domains, five non-reused IAM/STS/key
responsibilities, and exact-version S3 evidence for IAM/STS, WORM manifest,
independent readback, and the second fault domain.  The WORM entry must use
Object Lock `COMPLIANCE` and a retention deadline later than the attestation
expiry.  The validator only checks signed claims; it does not turn a fixture,
local key, or a same-host receipt into deployment evidence.

The command accepts `--offline` only for inspecting an already signed artifact
without an expiry check.  Offline verification is not a production
deployment attestation and must not be passed to an admission gate.

## Linux deployment acceptance preflight

The following read-only command is the operator entry point for P1-03/P1-04/P1-05.
It does not start or stop services, mutate namespaces, consume a challenge, or
upgrade the Stage-C inventory. Run the static check in CI and the live check as
root on the Linux host after the units and three namespaces have been installed:

```bash
# Repository/unit check (safe on macOS and CI; no external claims)
.venv/bin/python scripts/linux_deployment_preflight.py \
  --mode static \
  --root /opt/okx-quant/demo-chaos/current \
  --output /secure-transfer/preflight-static.json

# Real host check; must be run as root on Linux.
/opt/okx-quant/demo-chaos/current/.venv/bin/python scripts/linux_deployment_preflight.py \
  --mode live \
  --root /opt/okx-quant/demo-chaos/current \
  --installed-unit okx-quant-stage-c-external-actor@${RUN_ID}.service \
  --installed-unit okx-quant-stage-c-challenge-consumer@${RUN_ID}.service \
  --attestation /secure-transfer/external-deployment-attestation.json \
  --public-key /etc/okx-quant/stage-c/keys/deployment-verifier-public.pem \
  --expected-candidate-sha256 "${CANDIDATE_SHA256}" \
  --require-attestation \
  --output /secure-transfer/preflight-live-${RUN_ID}.json
```

Live mode fails closed unless `systemd-analyze verify`, the repository hardening
checker, `systemctl cat/show`, and distinct `ip netns` inodes all pass. The
attestation is verified with expiry checking and exact candidate binding; its
four S3 exact-version evidence objects are still independently checked by the
admission gate. A successful report has `preflight_only=true`; it is an
operational diagnostic and is never itself a `DEPLOYMENT_ATTESTED` receipt. If
the host is not Linux, systemd is not installed, a namespace is missing/reused,
or the independent attestation is absent, the command exits non-zero.

## Remaining external proof

Do not set `EXECUTOR_SHIPPED` or `DEPLOYMENT_ATTESTED` from these files alone.
Required external evidence includes successful `systemd-analyze verify`, live
role-scoped STS identities, the DynamoDB conditional consume, OKX Demo
requests, independent provider receipt, cleanup postconditions, WORM object
versions/retention and second-domain exact-version readback.
