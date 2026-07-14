import json
import boto3
import datetime


def lambda_handler(event, context):
    """
    CloudSentinel Automated Incident Responder
    ==========================================
    Triggered by EventBridge when GuardDuty detects a HIGH severity finding.

    Current mode: Simulation / logging mode.
    This function does not modify infrastructure yet. It logs incident details
    and shows what automated response actions would be taken.
    """

    detection_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print("=" * 70)
    print("CLOUDSENTINEL - HIGH SEVERITY INCIDENT DETECTED")
    print("=" * 70)
    print(f"Detection Timestamp UTC: {detection_time}")

    # EventBridge sends the GuardDuty finding inside the "detail" object.
    finding = event.get("detail", {})

    finding_id = finding.get("id", "Unknown")
    finding_type = finding.get("type", "Unknown")
    severity = finding.get("severity", 0)
    region = finding.get("region", "Unknown")
    account_id = finding.get("accountId", "Unknown")
    description = finding.get("description", "No description available")

    print(f"Finding ID:   {finding_id}")
    print(f"Finding Type: {finding_type}")
    print(f"Severity:     {severity}/10")
    print(f"AWS Region:   {region}")
    print(f"Account ID:   {account_id}")
    print(f"Description:  {description}")
    print("-" * 70)

    # Categorize severity.
    if severity >= 9:
        severity_label = "CRITICAL"
    elif severity >= 7:
        severity_label = "HIGH"
    elif severity >= 4:
        severity_label = "MEDIUM"
    else:
        severity_label = "LOW"

    print(f"Severity Level: {severity_label}")

    # Check whether the finding includes affected AWS resources.
    resources = finding.get("resources", [])
    compromised_instances = []

    for resource in resources:
        resource_type = resource.get("type", "Unknown")

        if resource_type == "Instance":
            instance_details = resource.get("instanceDetails", {})
            instance_id = instance_details.get("instanceId", "Unknown")
            instance_type = instance_details.get("instanceType", "Unknown")

            compromised_instances.append(instance_id)

            print("COMPROMISED EC2 INSTANCE DETECTED")
            print(f"Instance ID:   {instance_id}")
            print(f"Instance Type: {instance_type}")

            # Production response idea:
            # In a real SOC environment, this section could isolate the instance
            # by moving it to a quarantine security group.
            #
            # ec2 = boto3.client("ec2", region_name=region)
            # ec2.modify_instance_attribute(
            #     InstanceId=instance_id,
            #     Groups=["sg-QUARANTINE-ID"]
            # )
            #
            # For this lab, we keep the action simulated for safety.

            print(f"ACTION SIMULATED: Would isolate EC2 instance {instance_id}")
            print("ACTION SIMULATED: Would restrict network access using a quarantine security group")

    # Check for credential-related finding types.
    if "UnauthorizedAccess" in finding_type or "CredentialAccess" in finding_type:
        print("CREDENTIAL COMPROMISE SUSPECTED")
        print("ACTION SIMULATED: Would rotate IAM credentials")
        print("ACTION SIMULATED: Would invalidate active sessions")
        print("ACTION SIMULATED: Would review CloudTrail for related API activity")

    print("=" * 70)
    print("Incident logged. SOC analyst notification handled through SNS.")
    print("=" * 70)

    return {
        "statusCode": 200,
        "incident": {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "severity": severity,
            "severity_label": severity_label,
            "region": region,
            "account_id": account_id,
            "description": description,
            "compromised_instances": compromised_instances,
            "detection_timestamp": detection_time,
            "responder": "CloudSentinel-Lambda-v1",
            "mode": "simulation"
        }
    }
