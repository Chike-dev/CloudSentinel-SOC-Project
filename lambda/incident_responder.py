"""
CloudSentinel incident responder.

Consumes native GuardDuty finding events delivered by EventBridge, extracts
the affected EC2 instance where possible, and emits a single structured JSON
record to CloudWatch Logs. Enforcement is gated behind DRY_RUN (default true)
so the function is safe to deploy before real containment is wired in.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() != "false"

_SEVERITY_THRESHOLDS = (
    (9, "CRITICAL"),
    (7, "HIGH"),
    (4, "MEDIUM"),
    (0, "LOW"),
)


def severity_label(severity):
    for threshold, label in _SEVERITY_THRESHOLDS:
        if severity >= threshold:
            return label
    return "LOW"


def extract_instance_ids(finding):
    """
    Pull EC2 instance IDs out of a native GuardDuty finding.

    Handles Instance-type findings directly and AccessKey-type findings by
    parsing the session name out of principalId — for instance-profile
    credentials the session name is the source instance ID, which is the
    only way to identify the workload behind an OutsideAWS finding when
    instanceDetails is absent.
    """
    instance_ids = []
    resource = finding.get("resource", {}) or {}

    instance_id = (resource.get("instanceDetails") or {}).get("instanceId")
    if instance_id:
        instance_ids.append(instance_id)

    if resource.get("resourceType") == "AccessKey" and not instance_ids:
        principal_id = (resource.get("accessKeyDetails") or {}).get("principalId", "")
        if ":" in principal_id:
            session_name = principal_id.split(":", 1)[1]
            if session_name.startswith("i-"):
                instance_ids.append(session_name)

    return instance_ids


def build_planned_actions(finding_type, instance_ids):
    actions = []
    for iid in instance_ids:
        actions.append({
            "action": "quarantine_ec2",
            "instance_id": iid,
            "detail": "Move to quarantine security group",
        })
    if "UnauthorizedAccess" in finding_type or "CredentialAccess" in finding_type:
        actions.append({
            "action": "revoke_role_sessions",
            "detail": "Attach AWSRevokeOlderSessions policy to the affected role",
        })
        actions.append({
            "action": "review_cloudtrail",
            "detail": "Correlate API activity for the affected principal",
        })
    return actions


def lambda_handler(event, context):
    finding = event.get("detail", {}) or {}
    service = finding.get("service", {}) or {}
    resource = finding.get("resource", {}) or {}

    finding_type = finding.get("type", "Unknown")
    severity = finding.get("severity", 0)
    instance_ids = extract_instance_ids(finding)

    incident = {
        "responder": "CloudSentinel-Lambda",
        "mode": "dry_run" if DRY_RUN else "enforce",
        "response_time_utc": datetime.now(timezone.utc).isoformat(),
        "finding": {
            "id": finding.get("id"),
            "type": finding_type,
            "severity": severity,
            "severity_label": severity_label(severity),
            "region": finding.get("region"),
            "account_id": finding.get("accountId"),
            "title": finding.get("title"),
            "description": finding.get("description"),
            "detection_first_seen_utc": service.get("eventFirstSeen"),
            "detection_last_seen_utc": service.get("eventLastSeen"),
        },
        "affected": {
            "resource_type": resource.get("resourceType"),
            "instance_ids": instance_ids,
        },
        "planned_actions": build_planned_actions(finding_type, instance_ids),
    }

    logger.info(json.dumps(incident))

    if not DRY_RUN:
        # Enforcement is intentionally not implemented in this build; the
        # branch exists so future changes can wire in quarantine, session
        # revocation, and evidence preservation behind the same gate.
        pass

    return {"statusCode": 200, "incident": incident}
