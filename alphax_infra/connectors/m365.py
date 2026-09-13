# Copyright (c) 2026, Neotec Integrated Solutions
"""
Microsoft 365 connector — device compliance and mailbox protection posture.

Read-only scopes:
    DeviceManagementManagedDevices.Read.All,
    DeviceManagementConfiguration.Read.All,
    Device.Read.All, Directory.Read.All

Intune is where endpoint evidence comes from without touching an endpoint.
Encryption state, patch level, jailbreak status and compliance verdict all
arrive as vendor-asserted facts, which is a stronger evidence tier than a
screenshot and a weaker one than an independent scan; the confidence value
records that honestly rather than pretending it is ground truth.
"""

from __future__ import annotations

from .base import ConnectorResult, get_paged, oauth_token, register

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"

SCOPES = (
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "Device.Read.All",
    "Directory.Read.All",
)

# Graph attribute -> fact key. Written out rather than derived by snake-casing
# at runtime: a fact key that only exists as an f-string cannot be grepped,
# cannot be reviewed against the check catalogue, and silently disappears when
# Microsoft renames an attribute. The test suite asserts that every fact key a
# shipped check reads is emitted by a connector, and that assertion is only
# meaningful if the keys are literals.
POLICY_FACTS = {
    "passwordRequired": "compliance_policy.password_required",
    "passwordMinimumLength": "compliance_policy.password_minimum_length",
    "storageRequireEncryption": "compliance_policy.storage_require_encryption",
    "securityRequireSafetyNetAttestationBasicIntegrity": "compliance_policy.safetynet_attestation",
    "osMinimumVersion": "compliance_policy.os_minimum_version",
}

# Intune reports what the agent last told it. That is authoritative for the
# management state and merely indicative for the host's live posture.
VENDOR_ASSERTED_CONFIDENCE = 85


@register(
    key="m365",
    label="Microsoft 365 / Intune",
    vendor="Microsoft",
    scopes=SCOPES,
    description="Managed device inventory, compliance and encryption posture from Intune.",
)
def fetch(creds: dict) -> ConnectorResult:
    result = ConnectorResult()
    token = oauth_token(creds["tenant_id"], creds["client_id"], creds["client_secret"], SCOPE)
    _managed_devices(token, result)
    _compliance_policies(token, result)
    return result


def _managed_devices(token: str, result: ConnectorResult) -> None:
    fields = (
        "id,deviceName,managedDeviceName,operatingSystem,osVersion,complianceState,"
        "isEncrypted,jailBroken,manufacturer,model,serialNumber,azureADDeviceId,"
        "lastSyncDateTime,enrolledDateTime,managementAgent,userPrincipalName,"
        "deviceEnrollmentType,ethernetMacAddress,wiFiMacAddress"
    )
    devices = get_paged(
        f"{GRAPH}/deviceManagement/managedDevices",
        token,
        result,
        params={"$select": fields, "$top": "500"},
    )

    for d in devices:
        did = d.get("id")
        if not did:
            continue
        subject = f"device:{did}"
        name = d.get("deviceName") or d.get("managedDeviceName") or did

        result.observe(subject, "device.name", name)
        result.observe(subject, "device.os", d.get("operatingSystem"))
        result.observe(subject, "device.os_version", d.get("osVersion"))
        result.observe(
            subject,
            "device.compliance_state",
            d.get("complianceState"),
            confidence=VENDOR_ASSERTED_CONFIDENCE,
        )
        result.observe(
            subject,
            "device.encrypted",
            bool(d.get("isEncrypted")),
            confidence=VENDOR_ASSERTED_CONFIDENCE,
        )
        result.observe(subject, "device.jailbroken", str(d.get("jailBroken") or "").lower() == "true")
        result.observe(subject, "device.manufacturer", d.get("manufacturer"))
        result.observe(subject, "device.model", d.get("model"))
        result.observe(subject, "device.last_sync", d.get("lastSyncDateTime"))
        result.observe(subject, "device.enrolled", d.get("enrolledDateTime"))
        result.observe(subject, "device.management_agent", d.get("managementAgent"))
        result.observe(subject, "device.enrollment_type", d.get("deviceEnrollmentType"))
        result.observe(subject, "device.managed", True)

        identifiers = [
            {"identifier_type": "intune_device_id", "identifier_value": did},
            {"identifier_type": "entra_object_id", "identifier_value": d.get("azureADDeviceId") or ""},
            {"identifier_type": "serial_number", "identifier_value": d.get("serialNumber") or ""},
            {"identifier_type": "hostname", "identifier_value": name},
        ]
        for mac in (d.get("ethernetMacAddress"), d.get("wiFiMacAddress")):
            if mac:
                identifiers.append({"identifier_type": "mac_address", "identifier_value": mac})

        result.asset(
            "Endpoint",
            name,
            identifiers,
            hostname=name,
            os_version=f"{d.get('operatingSystem') or ''} {d.get('osVersion') or ''}".strip(),
            make_model=f"{d.get('manufacturer') or ''} {d.get('model') or ''}".strip(),
            serial_number=d.get("serialNumber"),
        )


def _compliance_policies(token: str, result: ConnectorResult) -> None:
    policies = get_paged(f"{GRAPH}/deviceManagement/deviceCompliancePolicies", token, result)
    result.observe("tenant:current", "intune.compliance_policy_count", len(policies))
    for p in policies:
        subject = f"compliance_policy:{p.get('id')}"
        result.observe(subject, "compliance_policy.name", p.get("displayName"))
        result.observe(subject, "compliance_policy.platform", (p.get("@odata.type") or "").rsplit(".", 1)[-1])
        for graph_key, fact_key in POLICY_FACTS.items():
            if graph_key in p:
                result.observe(subject, fact_key, p.get(graph_key))
