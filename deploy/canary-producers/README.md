# Canary external-producer deployment

This directory is the production deployment contract for Canary admission.
The collector, source signer, capability builder, and validators are
implemented; checked-in templates are not evidence that a real producer is
ready. Production remains fail-closed until all 12 real collectors have
successfully produced short-lived, WORM-read-back evidence for the exact
epoch, release, target, account, configuration, challenge, and credential.

## Trust separation

Each producer has a distinct collector user, signer user, Ed25519 key, IAM
principal, collector unit, signer unit, raw path, and signed path. The
collector may access only its frozen endpoint/file and raw directory. The
networkless signer reads but cannot own or write the raw source and recomputes
facts from the exact bytes. The independent `oqc-capability` authority can
only read signed artifacts and WORM readbacks; its private key is supplied as
a systemd credential and is disjoint from epoch, risk, operator, source, IAM,
and post-start verifier keys.

The following files must be installed from reviewed templates:

- `inventory.json`: exact 12-producer identity and request hashes;
- `NN-collector.json`: exact endpoint/file, method, version, credential
  fingerprint, credential-header names, required response headers, timeout;
- `NN-context.json`: exact phase and epoch/transition/runtime bindings;
- `capability-manifest.json`: exact absolute locations of all 12 readiness
  artifacts, public keys, IAM receipts, WORM readbacks, and root artifacts.

No `CHANGE_ME` value is deployable. Request JSON is canonicalized and its
SHA-256 must equal the value pre-registered in the signed soak epoch inventory.

## Fail-closed promotion sequence

1. Review the 12 collector requests, IAM least-privilege policies, key
   fingerprints, and the target credential fingerprint. Freeze their hashes
   into the inventory before signing the soak epoch.
2. Generate a fresh pre-start challenge. Run the seven pre-start collector and
   signer instances. Build the dual-signed transition only from those
   independently signed artifacts.
3. Run all 12 capability-phase collectors/signers for that same epoch,
   challenge, transition, target, release, configuration, and account.
4. Upload every readiness artifact to versioned Object Lock storage, perform
   an exact `versionId` readback, and stage the downloaded bytes plus the
   signed IAM/STS receipts. A copied local artifact is not a readback.
5. Run the deployment verifier from its isolated host/unit. Then invoke
   `okx-quant-canary-capability@<unique-readiness-token>.service`. The unit is
   networkless and creates a new immutable output; it refuses to overwrite an
   existing token.
6. Run the production gate with that exact capability bundle. The gate places
   the raw bundle SHA-256 in the admission request. Approval and deployment
   receipt must reproduce the same SHA-256, so a later bundle substitution
   fails.
7. Start Canary in its hard HALTED latch. Run the five post-start producers
   against the runtime startup nonce and startup hard epoch. Only the
   independently verified, operator+risk-signed activation may release that
   exact latch. Any later hard incident remains unreleasable by the old
   activation.

## Required negative checks

Before promotion, prove that the gate rejects one-at-a-time mutations of:
endpoint/request hash, source key, IAM principal or receipt, WORM version/KMS/
Object-Lock metadata, release/config/account/target identity, epoch/challenge,
runtime nonce/hard epoch, collector or signer unit/cgroup/invocation, raw
bytes, and capability replay binding.

Operational evidence still external to this repository is deliberately an
open readiness item: real OKX/API-admin responses, alert delivery receipt,
exact-version backup restore, systemd runtime observation, IAM/STS receipts,
Object Lock retention/KMS metadata, and the independent-host deployment
verifier. Missing, stale, placeholder, locally synthesized, or partially
covered evidence blocks production.
