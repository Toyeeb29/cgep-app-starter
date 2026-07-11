# Capstone Write-up: Patient Intake API — HIPAA-Controlled System

**Author:** Toyeeb (Toyeeb29)
**Framework:** HIPAA Security Rule
**Repo:** https://github.com/Toyeeb29/cgep-app-starter

## Executive summary

The starter Patient Intake API worked but could not survive an audit: PHI sat
under AWS-owned encryption keys, transited without a TLS mandate, was
unrecoverable after overwrite, was accessible through wildcard IAM, and left
no audit trail at the API edge. This capstone closes six of the eight named
gaps with a three-layer control system — Terraform baseline remediation, a
fail-closed Rego policy suite in CI, and OSCAL traceability to signed,
vaulted evidence — without breaking the workload. The post-remediation smoke
test returns the same `{"submission_id": ..., "status": "received"}` as day one.

## Framework selection

See `docs/framework-justification.md`. In brief: a telehealth intake system
handling PHI is a HIPAA covered-entity workload; compliance is a legal
obligation, and six of the eight starter gaps cite HIPAA Security Rule
sections directly, producing the tightest gap→control→evidence traceability.

## Gaps addressed (6 of 8)

| Gap | HIPAA | Fix (Terraform) | Detection (Rego) |
|---|---|---|---|
| GAP-01 S3 not CMK | 164.312(a)(2)(iv) | `baseline_kms.tf` + `baseline_s3.tf` (SSE-KMS, CMK, rotation) | `gap01_s3_cmk_encryption.rego` |
| GAP-02 DynamoDB not CMK | 164.312(a)(2)(iv) | `dynamodb_override.tf` (CMK via override) | `gap02_dynamodb_cmk.rego` |
| GAP-03 no TLS deny | 164.312(e)(1) | `baseline_s3.tf` (SecureTransport deny policy) | `gap03_s3_tls_only.rego` |
| GAP-04 no versioning | 164.308(a)(7) | `baseline_s3.tf` (versioning Enabled) | `gap04_s3_versioning.rego` |
| GAP-07 IAM wildcards | 164.312(a)(1) | `iam_override.tf` (PutItem/PutObject/KMS only) | `gap07_iam_least_privilege.rego` |
| GAP-08 no API logging | 164.312(b) | `apigw_logging.tf` + `apigw_override.tf` (access logs, 90d retention, throttling) | `gap08_apigw_logging.rego` |

GAP-05 (Lambda VPC) and GAP-06 (resilience) are documented as `planned` in the
OSCAL component with a link to the gap register — acknowledged, not hidden.

## The three layers

1. **Terraform baseline** — new files (`baseline_*.tf`, `apigw_logging.tf`) add
   missing resources; `*_override.tf` files merge fixes into the starter's
   resources without editing its code.
2. **Policy suite** — six Rego policies under `policies/` run in CI via
   Conftest and fail closed. Two policies required plan-time-unknown handling
   (checking configuration references rather than computed values), the same
   lesson as evaluating any freshly-initialized workspace without state.
3. **OSCAL** — `oscal/components/patient-intake-api.json` (trestle-validated)
   maps every closed gap to a NIST control, a HIPAA section, the exact
   Terraform resource, the enforcing policy, and a signed evidence bundle.

## Pipeline and chain of custody

`.github/workflows/grc-gate.yml` runs on every PR:
plan → conftest gate → bundle → Cosign keyless sign → upload to the
Object-Locked vault → enforce. Signing happens even on failing runs, so the
runs most worth investigating always leave signed evidence.

## The two-PR demonstration

- **Green PR (merged):** https://github.com/Toyeeb29/cgep-app-starter/pull/1
  — controls in place, `conftest failures: 0`, evidence signed and vaulted at
  `s3://cgep-lab-grc-evidence-vault-37bf1d7e/capstone/runs/29166181720/`.
- **Red PR (blocked, left open):** https://github.com/Toyeeb29/cgep-app-starter/pull/2
  — deliberately removes the S3 hardening; the gate detects GAP-01/03/04 and
  fails the build. The merge is blocked. The failed run still produced a
  signed bundle.

## How to verify (grader path)

1. Start at `oscal/components/patient-intake-api.json`; pick any implemented
   requirement and follow its `links[rel=evidence].href`.
2. Run the chain-of-custody check:
   `EVIDENCE_VAULT=cgep-lab-grc-evidence-vault-37bf1d7e bash scripts/verify-evidence.sh 29166181720`
   (script in the companion repo `Toyeeb29/cgep-labs`).
3. Re-introduce any addressed gap and run
   `conftest test --policy policies --all-namespaces terraform/plan.json` —
   the suite fails closed with the gap ID and HIPAA section in the message.

## What I'd do next

Close GAP-05 by attaching the Lambda to the provisioned VPC subnets with a
VPC endpoint for DynamoDB/S3; close GAP-06 with reserved concurrency, a DLQ,
and X-Ray; add a WAF to the API edge; and promote the Data Access-style audit
logging into a continuous-monitoring feed (the Lab 5.2 pattern) so evidence
generation isn't PR-bound.