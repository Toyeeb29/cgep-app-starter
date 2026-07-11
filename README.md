# cgep-app-starter

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## Grader verification (5 minutes)

This fork is a completed capstone submission (framework: **HIPAA Security Rule** — see `WRITEUP.md`).

1. **Policies fail closed:** `opa test ./policies` → 12/12 pass. Re-introduce any
   gap (e.g. delete `terraform/baseline_s3.tf`), regenerate the plan
   (`terraform plan -out=tfplan && terraform show -json tfplan > plan.json`),
   then `conftest test --policy policies --all-namespaces terraform/plan.json`
   → fails with the gap ID and HIPAA section in the message.
2. **Two-PR demo:** PR #1 (green, merged) and PR #2 (red, blocked, left open) —
   see the Actions history for the passing and failing gate runs.
3. **Chain of custody:** signed bundle at
   `s3://cgep-lab-grc-evidence-vault-37bf1d7e/capstone/runs/29166181720/`
   (Cosign sig bundle + SHA-256 sidecar). Verify:
   `cosign verify-blob --bundle <bundle>.sig.bundle --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <bundle>`
4. **OSCAL:** `oscal/components/patient-intake-api.json` (trestle-validated) maps
   each closed gap → NIST control → HIPAA section → Terraform resource → evidence link.
5. **Narrative:** `WRITEUP.md` covers framework choice, remediation, trade-offs,
   and what was deliberately left as planned (GAP-05/06).


## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## What you build on top

Fork the repo into your own `cgep-capstone` and add:

1. **Layer 1 — GRC baseline (Terraform).** KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.
2. **Layer 2 — OPA policy suite (Rego).** Five or more policies that catch the named gaps in [GAPS.md](GAPS.md). Each policy maps to at least one control from the framework you choose.
3. **Layer 3 — GitHub Actions pipeline.** Plan → Conftest gate → apply → Cosign sign → upload to vault.
4. **Layer 4 — OSCAL component.** A `component-definition.json` describing how your governed system implements its controls.

Full brief: `docs/labs/07_01_capstone_brief.md` in the course content repo.

## Framework mapping is required

Your capstone must declare a primary framework: **HIPAA Security Rule**, **SOC 2 Trust Services Criteria**, or **CMMC Level 2**. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's `control-implementations` reference your framework's catalog.

A starter mapping is in [FRAMEWORKS.md](FRAMEWORKS.md). It is not the only valid mapping. You're expected to defend yours.

## Cost

Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

## Layout

```
cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
    └── intake.sh
```

## License

MIT. Fork freely. Submissions remain learners' own work.
