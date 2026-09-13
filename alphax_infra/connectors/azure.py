# Copyright (c) 2026, Neotec Integrated Solutions
"""
Microsoft Azure connector — resource, exposure, encryption and logging posture.

Required role: Reader on the subscription, plus Key Vault Reader where vault
configuration is in scope. Nothing beyond read.

Azure is the third connector rather than the first because in KSA mid-market
tenants the identity findings land before the cloud ones. But it carries the
highest-severity checks in the catalogue: public storage, unrestricted network
security group rules and absent diagnostic logging are the three that turn an
assessment report into a signed remediation contract.
"""

from __future__ import annotations

from .base import ConnectorResult, get_paged, oauth_token, register

ARM = "https://management.azure.com"
SCOPE = "https://management.azure.com/.default"
API = "2021-04-01"

SCOPES = ("Reader (subscription)", "Key Vault Reader")

# Source ranges that mean "the entire internet" in an NSG rule.
ANY_SOURCE = {"*", "internet", "any", "0.0.0.0/0", "<nw>/0", "::/0"}

# Ports that should never be reachable from the internet on a managed estate.
SENSITIVE_PORTS = {"22", "3389", "1433", "3306", "5432", "27017", "6379", "9200", "445", "135"}


@register(
    key="azure",
    label="Microsoft Azure",
    vendor="Microsoft",
    scopes=SCOPES,
    description="Subscription resources, network exposure, storage encryption and diagnostic logging.",
)
def fetch(creds: dict) -> ConnectorResult:
    result = ConnectorResult()
    sub = creds.get("subscription_id")
    if not sub:
        result.ok = False
        result.error = "subscription_id is not set on this connector"
        return result

    token = oauth_token(creds["tenant_id"], creds["client_id"], creds["client_secret"], SCOPE)

    _resources(token, sub, result)
    _network_security_groups(token, sub, result)
    _storage_accounts(token, sub, result)
    _activity_log_profile(token, sub, result)
    return result


def _arm(path: str, api: str = API) -> str:
    return f"{ARM}{path}?api-version={api}"


def _resources(token: str, sub: str, result: ConnectorResult) -> None:
    items = get_paged(_arm(f"/subscriptions/{sub}/resources", "2021-04-01"), token, result,
                      next_key="nextLink")
    result.observe(f"subscription:{sub}", "subscription.resource_count", len(items))

    by_type: dict = {}
    for r in items:
        rid = r.get("id")
        rtype = r.get("type") or "unknown"
        by_type[rtype] = by_type.get(rtype, 0) + 1
        subject = f"azure:{rid}"

        result.observe(subject, "resource.name", r.get("name"))
        result.observe(subject, "resource.type", rtype)
        result.observe(subject, "resource.location", r.get("location"))
        result.observe(subject, "resource.tags", r.get("tags") or {})
        result.observe(subject, "resource.has_owner_tag",
                       bool((r.get("tags") or {}).get("owner") or (r.get("tags") or {}).get("Owner")))

        if rtype.lower() == "microsoft.compute/virtualmachines":
            result.asset(
                "Server",
                r.get("name") or rid,
                [{"identifier_type": "azure_resource_id", "identifier_value": rid}],
                hostname=r.get("name"),
            )

    result.observe(f"subscription:{sub}", "subscription.resource_types", by_type)
    # Data residency is a live PDPL question for every Saudi customer, so
    # region distribution is recorded as a fact rather than left to inference.
    regions = sorted({r.get("location") for r in items if r.get("location")})
    result.observe(f"subscription:{sub}", "subscription.regions", regions)
    result.observe(f"subscription:{sub}", "subscription.region_count", len(regions))


def _network_security_groups(token: str, sub: str, result: ConnectorResult) -> None:
    nsgs = get_paged(
        _arm(f"/subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups", "2023-05-01"),
        token, result, next_key="nextLink",
    )
    for nsg in nsgs:
        nid = nsg.get("id")
        subject = f"azure:{nid}"
        props = nsg.get("properties") or {}
        rules = (props.get("securityRules") or []) + (props.get("defaultSecurityRules") or [])

        result.observe(subject, "nsg.name", nsg.get("name"))
        result.observe(subject, "nsg.rule_count", len(rules))

        open_rules = []
        open_sensitive = []
        for rule in rules:
            rp = rule.get("properties") or {}
            if (rp.get("access") or "").lower() != "allow":
                continue
            if (rp.get("direction") or "").lower() != "inbound":
                continue

            sources = [str(s).lower() for s in
                       ((rp.get("sourceAddressPrefixes") or []) + [rp.get("sourceAddressPrefix") or ""])
                       if s]
            if not any(s in ANY_SOURCE for s in sources):
                continue

            ports = [str(p) for p in
                     ((rp.get("destinationPortRanges") or []) + [rp.get("destinationPortRange") or ""])
                     if p]
            open_rules.append({"name": rule.get("name"), "ports": ports})

            for p in ports:
                if p == "*" or p in SENSITIVE_PORTS or _range_covers(p, SENSITIVE_PORTS):
                    open_sensitive.append({"name": rule.get("name"), "port": p})
                    break

        result.observe(subject, "nsg.internet_open_rules", open_rules)
        result.observe(subject, "nsg.internet_open_rule_count", len(open_rules))
        result.observe(subject, "nsg.sensitive_port_exposed", bool(open_sensitive))
        result.observe(subject, "nsg.sensitive_port_rules", open_sensitive)


def _range_covers(spec: str, ports: set) -> bool:
    if "-" not in spec:
        return False
    try:
        lo, hi = (int(x) for x in spec.split("-", 1))
    except ValueError:
        return False
    return any(lo <= int(p) <= hi for p in ports)


def _storage_accounts(token: str, sub: str, result: ConnectorResult) -> None:
    accounts = get_paged(
        _arm(f"/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts", "2023-01-01"),
        token, result, next_key="nextLink",
    )
    for a in accounts:
        aid = a.get("id")
        subject = f"azure:{aid}"
        p = a.get("properties") or {}
        net = p.get("networkAcls") or {}
        enc = (p.get("encryption") or {}).get("services") or {}

        result.observe(subject, "storage.name", a.get("name"))
        result.observe(subject, "storage.https_only", bool(p.get("supportsHttpsTrafficOnly")))
        result.observe(subject, "storage.min_tls_version", p.get("minimumTlsVersion"))
        result.observe(subject, "storage.allow_blob_public_access", bool(p.get("allowBlobPublicAccess")))
        result.observe(subject, "storage.public_network_access", p.get("publicNetworkAccess"))
        result.observe(subject, "storage.network_default_action", net.get("defaultAction"))
        result.observe(subject, "storage.blob_encrypted", bool((enc.get("blob") or {}).get("enabled")))
        result.observe(subject, "storage.file_encrypted", bool((enc.get("file") or {}).get("enabled")))
        result.observe(subject, "storage.infrastructure_encryption",
                       bool((p.get("encryption") or {}).get("requireInfrastructureEncryption")))
        result.observe(subject, "storage.allow_shared_key_access",
                       bool(p.get("allowSharedKeyAccess", True)))


def _activity_log_profile(token: str, sub: str, result: ConnectorResult) -> None:
    """
    Whether the subscription ships its activity log anywhere durable.

    Maps directly to ISO A.8.15 and NCA ECC 2-12. A subscription with no
    diagnostic setting has no forensic record of who changed what, which is a
    finding an auditor will always raise and an operations team will always
    have meant to fix.
    """
    try:
        settings = get_paged(
            _arm(f"/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings",
                 "2021-05-01-preview"),
            token, result, next_key="nextLink", max_pages=5,
        )
    except Exception:  # noqa: BLE001 — absence is itself the observation
        settings = []

    subject = f"subscription:{sub}"
    destinations = []
    for s in settings:
        p = s.get("properties") or {}
        if p.get("workspaceId"):
            destinations.append("log_analytics")
        if p.get("storageAccountId"):
            destinations.append("storage")
        if p.get("eventHubAuthorizationRuleId"):
            destinations.append("event_hub")

    result.observe(subject, "subscription.activity_log_destinations", sorted(set(destinations)))
    result.observe(subject, "subscription.activity_log_exported", bool(destinations))
