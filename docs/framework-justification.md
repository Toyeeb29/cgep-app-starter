# Framework Selection: HIPAA Security Rule

## Justification

MedIntake Health is a telehealth provider whose Patient Intake API collects,
transmits, and stores protected health information (PHI) — patient identifiers,
intake reasons, and uploaded clinical documents — making it a covered entity
under HIPAA, where compliance is a legal obligation rather than a market choice.
The HIPAA Security Rule's technical safeguards map directly onto the workload's
architecture: encryption requirements (164.312(a)(2)(iv)) govern the DynamoDB
table and S3 bucket holding PHI, transmission security (164.312(e)(1)) governs
the API Gateway and Lambda networking, access control (164.312(a)(1)) governs
the Lambda IAM role, and audit controls (164.312(b)) govern API access logging.
Because six of the starter's eight named gaps cite HIPAA sections directly,
selecting HIPAA produces the tightest traceability from gap to control to
remediation to evidence — every policy, Terraform override, and OSCAL claim
in this capstone traces to a specific Security Rule safeguard.

## Gap-to-Control Mapping

| Gap | HIPAA Section | Safeguard | Remediation Layer |
|---|---|---|---|
| GAP-01: S3 SSE-S3 not CMK | 164.312(a)(2)(iv) | Encryption | Terraform + Policy |
| GAP-02: DynamoDB default key | 164.312(a)(2)(iv) | Encryption | Terraform + Policy |
| GAP-03: No TLS-only policy | 164.312(e)(1) | Transmission security | Terraform + Policy |
| GAP-04: No S3 versioning | 164.308(a)(7) | Contingency plan | Terraform + Policy |
| GAP-05: Lambda not in VPC | 164.312(e)(1) | Transmission security | Terraform |
| GAP-07: IAM wildcards | 164.312(a)(1) | Access control | Terraform + Policy |
| GAP-08: No API access logging | 164.312(b) | Audit controls | Terraform + Policy |

GAP-06 (Lambda resilience) is a SOC 2 CC7.2 concern without a direct HIPAA
Security Rule citation; it is addressed in Terraform as an operational
best practice and documented in OSCAL as supporting 164.308(a)(7)
contingency planning.
