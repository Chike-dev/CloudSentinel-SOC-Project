# CloudSentinel — Design Decisions

This document captures the major architectural decisions behind CloudSentinel. The goal is to show not only what was built, but why each decision was made.

---

## ADR-001 — Use AWS-native services for the first implementation

**Decision:** Build the first version using CloudTrail, S3, CloudWatch Logs, GuardDuty, Security Hub, EventBridge, Lambda, SNS, and IAM.

**Rationale:** AWS-native services reduce operational overhead and allow the project to focus on detection flow, event routing, and response logic instead of managing third-party infrastructure.

**Trade-off:** This keeps the project tightly coupled to AWS. A production SOC might also forward findings to a SIEM such as Splunk, Sentinel, Chronicle, or OpenSearch.

---

## ADR-002 — Use CloudTrail, S3, and CloudWatch Logs for audit evidence

**Decision:** Enable CloudTrail and send logs to a dedicated private S3 bucket and CloudWatch Logs.

**Rationale:** S3 provides durable evidence retention, while CloudWatch Logs provides operational visibility and faster review during investigation.

**Trade-off:** Storing logs in both places adds small cost and management overhead, but improves investigation value.

---

## ADR-003 — Use GuardDuty as the primary detector

**Decision:** Use GuardDuty as the main threat detection engine.

**Rationale:** GuardDuty provides managed AWS threat detection with severity-scored findings, reducing the need to write custom detection logic for the first version.

**Trade-off:** GuardDuty is a managed detector, so detection logic is not fully transparent or customizable.

---

## ADR-004 — Use Security Hub for aggregation, not as the automation source

**Decision:** Use Security Hub as the central findings dashboard, while EventBridge listens directly for GuardDuty findings.

**Rationale:** Direct GuardDuty-to-EventBridge routing simplifies the automation path and avoids relying on Security Hub ingestion timing for response triggers.

**Trade-off:** Some enterprises prefer routing all normalized findings through Security Hub. That model can be added later if multi-source automation becomes a goal.

---

## ADR-005 — Trigger response only for severity >= 7

**Decision:** EventBridge matches GuardDuty findings where severity is greater than or equal to 7.

**Rationale:** High-severity automation reduces alert fatigue and focuses response actions on higher-confidence or higher-impact findings.

**Trade-off:** Medium-severity findings may still be important but require manual review or a separate workflow.

---

## ADR-006 — Use SNS email for the first alert channel

**Decision:** Send alerts to an SNS email subscription.

**Rationale:** Email is simple, AWS-native, and easy to validate without third-party integrations.

**Trade-off:** Email is less operationally mature than PagerDuty, Slack, Teams, or a ticketing system.

---

## ADR-007 — Keep Lambda in simulation mode

**Decision:** Lambda parses and logs incident details, but does not automatically quarantine resources in v1.

**Rationale:** Simulation mode demonstrates response logic safely without modifying infrastructure during a lab exercise.

**Trade-off:** The current function does not fully contain incidents. Production hardening would require quarantine security groups, session revocation, permission reduction, and evidence preservation.

---

## ADR-008 — Use IAM roles instead of long-term credentials

**Decision:** Use IAM roles for EC2 and analyst access rather than embedding long-term AWS keys.

**Rationale:** Roles provide temporary credentials and model best-practice access patterns. The compromised EC2 simulation also becomes more realistic because attackers frequently abuse instance-profile credentials.

**Trade-off:** Roles require more setup and trust-policy understanding than static credentials.

---

## ADR-009 — Validate with sample findings before real attacks

**Decision:** Use GuardDuty sample findings as an integration test before running the real credential-exfiltration scenario.

**Rationale:** Sample findings safely prove that EventBridge, SNS, and Lambda are wired correctly. This separates pipeline problems from detection problems.

**Trade-off:** Sample findings are not real detection evidence and must be labeled clearly.

---



