# CloudSentinel — Attack Simulation and Validation Report

## Executive summary

CloudSentinel was validated using a two-stage strategy:

1. **Synthetic integration validation** using GuardDuty sample findings to confirm that the detection-to-response pipeline was wired correctly.
2. **Real detection validation** using an authorized EC2 instance-role credential-exfiltration scenario that produced a real high-severity GuardDuty finding.

This separation was intentional. Sample findings tested pipeline reliability; the credential-exfiltration scenario tested whether the system could respond to an actual cloud attack pattern.

**Environment:** AWS lab account
**Region:** `us-east-1`
**Date:** July 14, 2026

---

## Scope and authorization

All testing was performed against resources owned by the project account. The EC2 instance, IAM roles, GuardDuty configuration, EventBridge rule, SNS topic, and Lambda function were created specifically for this Project.

No third-party systems were targeted.

---

## Pipeline under test

```text
GuardDuty finding
      │
      ▼
EventBridge rule: cloudsentinel-guardduty-high-severity
      │
      ├── SNS topic: cloudsentinel-alerts
      │       └── email notification
      │
      └── Lambda: cloudsentinel-incident-responder
              └── incident parsing and response logging
```

The EventBridge rule matches GuardDuty findings with severity `>= 7`.

---

## Phase 1 — Synthetic pipeline validation

### Objective

Confirm that GuardDuty findings could flow through EventBridge to both downstream response targets before relying on live attacker behavior.

### Method

GuardDuty sample findings were generated from the AWS console.

Sample findings are useful because they exercise the same event path as real findings while being clearly marked as sample data. They are appropriate for validating integrations, alerts, and response functions.

### Results

| Pipeline stage | Result | Evidence |
|---|---|---|
| GuardDuty | Generated sample findings, including high and critical severity | `screenshots/11-guardduty-sample-findings.png` |
| Security Hub | Aggregated the findings into the SOC dashboard | `screenshots/12-SecurityHub-sample-findings.png` |
| SNS | Delivered the CloudSentinel email alert | `screenshots/13-sns-email-alert.png` |
| Lambda | Executed and logged incident details in CloudWatch Logs | `screenshots/14-lambda-cloudwatch-logs.png` |

### Interpretation

This phase validated the integration path. It did not prove real attacker detection because the findings were synthetic. The findings are therefore documented as pipeline validation evidence only.

---

## Phase 2 — Real detection validation: EC2 role credential exfiltration

### Objective

Simulate a realistic post-compromise cloud attack in which an attacker gains access to an EC2 instance, enumerates the AWS account, extracts temporary instance-role credentials, and uses those credentials from outside AWS.

### Initial reconnaissance observation

Basic enumeration commands from the EC2 instance were successfully executed, including identity discovery, S3 bucket listing, IAM user listing, IAM role listing, and region enumeration.

This activity represented valid post-compromise reconnaissance, but it did not reliably produce a GuardDuty finding at severity `>= 7`. This was treated as a detection-engineering observation rather than a pipeline failure: low-signal enumeration is not guaranteed to cross a high-severity automation threshold.

Evidence: `screenshots/15-simulation-a-recon-commands.png`

### Credential-exfiltration scenario

The scenario was escalated into a higher-fidelity cloud attack by using the EC2 instance role credentials from an external machine. This models an attacker moving temporary credentials off the compromised workload and using them outside the expected EC2 context.

Evidence: `screenshots/15b-credential-exfiltration-external.png`

### Detection result

GuardDuty independently generated the following real finding:

| Attribute | Value |
|---|---|
| Finding type | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` |
| Severity | 8 / 10 — High |
| Region | `us-east-1` |
| Detection source | GuardDuty |
| Approximate detection time | ~24 minutes |
| Sample finding? | No |

Evidence: `screenshots/16-real-finding-guardduty.png`

### Response result

Because the finding severity was above the EventBridge threshold, the response pipeline executed automatically.

| Response target | Result | Evidence |
|---|---|---|
| SNS | Email alert delivered to analyst inbox | `screenshots/17-real-finding-email.png` |
| Security Hub | Finding aggregated in centralized dashboard | `screenshots/18-securityhub-real-finding.png` |
| Lambda | Incident responder parsed and logged the finding | CloudWatch Logs evidence from responder execution |

---

## Incident-response lesson learned

Terminating the compromised EC2 instance did not immediately invalidate already-exfiltrated temporary credentials. This is expected behavior: the stolen credentials were IAM role session credentials, and those credentials remain valid until expiry unless the role sessions are explicitly revoked or the permissions are otherwise restricted.

A stronger production response would include:

- revoking active sessions for the affected role,
- reducing or removing permissions from the compromised role,
- preserving evidence from the instance,
- reviewing CloudTrail for actions taken with the stolen credentials,
- rotating any related long-term credentials if discovered,
- and documenting the timeline from credential theft to detection and containment.

This finding directly informed the production-hardening roadmap for the Lambda responder.

---

## Evidence summary

| Screenshot | Purpose |
|---|---|
| `11-guardduty-sample-findings.png` | Synthetic GuardDuty findings generated for integration testing |
| `12-SecurityHub-sample-findings.png` | Security Hub aggregation of sample findings |
| `13-sns-email-alert.png` | SNS alert delivery during pipeline validation |
| `14-lambda-cloudwatch-logs.png` | Lambda execution during pipeline validation |
| `15-simulation-a-recon-commands.png` | Sanitized EC2 internal reconnaissance evidence |
| `15b-credential-exfiltration-external.png` | External use of EC2 role credentials |
| `16-real-finding-guardduty.png` | Real GuardDuty credential-exfiltration finding |
| `17-real-finding-email.png` | Real finding email alert |
| `18-securityhub-real-finding.png` | Real finding aggregated in Security Hub |

---

## Simulation B — planned v2 extension

External port scanning was not included in this version. The planned extension will enable VPC Flow Logs and perform authorized network reconnaissance against the lab EC2 instance to validate GuardDuty network-reconnaissance detections such as port probing.

This is documented as roadmap work rather than claimed as completed validation.

---

## Conclusion

CloudSentinel successfully demonstrated an AWS-native detection and response workflow. The pipeline was first validated with sample findings, then validated against a real credential-exfiltration scenario that produced a high-severity GuardDuty finding and triggered the automated response path.

The strongest engineering outcome was not only that the pipeline worked, but that the validation process revealed an important cloud incident-response lesson: removing the compromised instance is not sufficient once temporary role credentials have been exfiltrated.
