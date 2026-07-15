import importlib
import json
from pathlib import Path

import pytest

import incident_responder as responder


FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def _default_dry_run(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    importlib.reload(responder)


def test_credential_exfiltration_resolves_instance_from_principal_id():
    event = _load("guardduty_credential_exfiltration.json")
    result = responder.lambda_handler(event, context=None)

    assert result["statusCode"] == 200
    incident = result["incident"]
    assert incident["affected"]["instance_ids"] == ["i-0123456789abcdef0"]
    assert incident["affected"]["resource_type"] == "AccessKey"
    assert incident["finding"]["severity_label"] == "HIGH"
    assert incident["mode"] == "dry_run"
    assert incident["finding"]["detection_first_seen_utc"] == "2026-07-14T17:36:00Z"
    assert any(a["action"] == "revoke_role_sessions" for a in incident["planned_actions"])
    assert any(a["action"] == "quarantine_ec2" for a in incident["planned_actions"])


def test_instance_finding_resolves_instance_from_instance_details():
    event = _load("guardduty_instance_finding.json")
    result = responder.lambda_handler(event, context=None)

    incident = result["incident"]
    assert incident["affected"]["instance_ids"] == ["i-instancefinding"]
    assert incident["affected"]["resource_type"] == "Instance"
    # Backdoor:EC2 is neither UnauthorizedAccess nor CredentialAccess — no
    # credential-response actions should be planned.
    assert not any(a["action"] == "revoke_role_sessions" for a in incident["planned_actions"])
    assert any(a["action"] == "quarantine_ec2" for a in incident["planned_actions"])


def test_regression_reads_singular_resource_not_plural_resources():
    """
    The pre-fix responder iterated event['detail']['resources'] (plural, ASFF
    schema). EventBridge delivers native GuardDuty findings with a singular
    'resource' object. This test guards against reintroducing the ASFF shape,
    which caused the function to silently no-op on real findings.
    """
    event = {
        "detail": {
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "severity": 8,
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "principalId": "AROAEXAMPLE:i-regression",
                    "userType": "AssumedRole",
                    "userName": "SomeRole",
                },
            },
        }
    }
    result = responder.lambda_handler(event, context=None)
    assert result["incident"]["affected"]["instance_ids"] == ["i-regression"]


def test_severity_labels_partition_the_scale():
    assert responder.severity_label(10) == "CRITICAL"
    assert responder.severity_label(9) == "CRITICAL"
    assert responder.severity_label(8) == "HIGH"
    assert responder.severity_label(7) == "HIGH"
    assert responder.severity_label(6) == "MEDIUM"
    assert responder.severity_label(4) == "MEDIUM"
    assert responder.severity_label(3) == "LOW"
    assert responder.severity_label(0) == "LOW"


def test_dry_run_defaults_true_when_env_unset(monkeypatch):
    monkeypatch.delenv("DRY_RUN", raising=False)
    importlib.reload(responder)
    assert responder.DRY_RUN is True


def test_dry_run_disabled_when_env_is_false(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    importlib.reload(responder)
    assert responder.DRY_RUN is False


def test_empty_event_does_not_crash():
    result = responder.lambda_handler({}, context=None)
    assert result["statusCode"] == 200
    assert result["incident"]["affected"]["instance_ids"] == []
