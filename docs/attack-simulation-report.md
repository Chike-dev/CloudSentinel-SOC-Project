# CloudSentinel — Attack Simulation Report

This report documents how the CloudSentinel SOC pipeline was validated: first with
synthetic sample findings to confirm the detection-to-alert wiring, then with a
**real** simulated attack that GuardDuty detected on its own.

**Environment:** AWS account, region `us-east-1`
**Date:** July 14, 2026

---

## Phase 1 — Pipeline Validation (GuardDuty Sample Findings)

**Method:** GuardDuty → Settings → Sample findings → Generate
**Purpose:** Confirm the full path works end to end *before* running a real attack.

GuardDuty sample findings are real finding objects flagged with `"sample": true`.
They exercise the same pipeline a genuine finding would, so they are a safe way to
prove the wiring without waiting on a live attacker.

### Result — pipeline confirmed working

| Stage | Evidence | Screenshot |
|-------|----------|------------|
| GuardDuty raised findings | 404 findings incl. 160 High / 11 Critical | `11-guardduty-sample-findings.png` |
| Security Hub aggregated them | Findings ingested via integration | `12-SecurityHub-sample-findings.png` |
| SNS delivered email alert | CloudSentinel alerts received in inbox | `13-sns-email-alert.png` |
| Lambda incident responder executed | Incident output in CloudWatch Logs | `14-lambda-cloudwatch-logs.png` |

**Example finding delivered:** `Execution:Runtime/ReverseShell`, severity 8/10.

> Note: These were GuardDuty **sample** findings (`"sample": true`), used only to
> validate the pipeline. The real detection is documented in Simulation A below.

---

## Simulation A — Compromised EC2: Credential Exfiltration & Internal Recon

**Attacker position:** Started inside a compromised EC2 instance, then moved the
instance's IAM role credentials off-box to an external machine.
**Goal:** Reproduce real post-compromise behavior — enumerate the account, steal the
instance role credentials, and use them from outside AWS.

### Attack steps executed

| Step | Action | Attacker intent |
|------|--------|-----------------|
| 1 | `aws sts get-caller-identity` (inside EC2) | Confirm the compromised identity |
| 2 | `aws s3 ls`, `aws iam list-users`, `aws iam list-roles`, `aws ec2 describe-regions` | Enumerate the account for targets |
| 3 | Pulled role credentials from the instance metadata service (IMDSv2) | Steal the instance's temporary credentials |
| 4 | Set the stolen credentials on an external laptop, ran `aws sts get-caller-identity` and `aws s3 ls` | Use the stolen credentials from outside AWS |

Recon evidence (sanitized): `15-simulation-a-recon-commands.png`
Credential exfiltration in action: `15b-credential-exfiltration-external.png` — note the
`assumed-role/CloudSentinel-EC2ReconRole` identity being used from an external machine.

### Detection result — REAL finding (not a sample)

| Attribute | Value |
|-----------|-------|
| **Finding type** | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` |
| **Severity** | 8 / 10 (HIGH) |
| **Region** | `us-east-1` |
| **Time to detection** | ~24 minutes from trigger to finding |
| **Pipeline response** | EventBridge matched (severity ≥ 7) → SNS email delivered + Lambda incident responder logged the incident |

Evidence:
- `16-real-finding-guardduty.png` — GuardDuty finding detail (external IP redacted)
- `17-real-finding-email.png` — SNS alert email delivered to inbox
- `18-securityhub-real-finding.png` — same finding aggregated in Security Hub

### Why this matters

Credential exfiltration is one of the highest-fidelity indicators of compromise in
AWS — legitimate workloads never move an instance's role credentials off the instance.
Unlike the sample findings, GuardDuty detected this one on its own, from real activity,
and the full pipeline responded automatically.

**Incident-response insight discovered during the simulation:** terminating the
compromised EC2 instance did **not** immediately invalidate the stolen credentials.
Instance-role credentials are temporary security tokens validated by AWS IAM, not by
the instance itself, so they remain valid until they expire regardless of whether the
source instance still exists. Cutting off an attacker who has already exfiltrated
credentials requires waiting for token expiry or explicitly revoking the role's active
sessions — not just deleting the instance. This mirrors the credential-rotation logic
outlined in the Lambda responder.

---

## Simulation B — External Port Scanning (Planned, v2)

Not included in this version. A planned extension will enable VPC Flow Logs and run an
external `nmap` scan against the instance's public IP to trigger network-reconnaissance
detection (`Recon:EC2/PortProbeUnprotectedPort`). This is documented as a roadmap item
rather than claimed as completed work.

---

## Summary

| | Sample validation | Real attack (Simulation A) |
|---|---|---|
| Detection | ✅ GuardDuty | ✅ GuardDuty (unprompted) |
| Aggregation | ✅ Security Hub | ✅ Security Hub |
| Alerting | ✅ SNS email | ✅ SNS email |
| Automated response | ✅ Lambda | ✅ Lambda |

The CloudSentinel pipeline detects, aggregates, alerts on, and responds to security
findings end to end — validated with both synthetic samples and a genuine simulated
attack.
