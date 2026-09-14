# Copyright (c) 2026, Neotec Integrated Solutions
"""
Microsoft Entra ID connector.

Entra is the first connector because identity is where the assessment findings
are. In a typical KSA mid-market tenant this one connector supplies evidence
for a large share of the access-control clauses in both ISO 27001 Annex A and
NCA ECC-2 domain 2-2, with no agent, no inbound firewall change and no
credential held by us beyond a read-only app registration the customer can
revoke from their own portal in one click.

Required application permissions, all read-only:
    User.Read.All, Group.Read.All, Directory.Read.All,
    UserAuthenticationMethod.Read.All, Policy.Read.All,
    AuditLog.Read.All, Application.Read.All, RoleManagement.Read.Directory

Data minimisation applied here:
  - authentication methods are reduced to which *kinds* are registered, never
    phone numbers or device names
  - sign-in data is reduced to a timestamp, never IPs or locations
  - no password hashes, no credentials, no group membership payloads beyond
    privileged roles
"""

from __future__ import annotations

from .base import ConnectorResult, get_paged, oauth_token, register

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
SCOPE = "https://graph.microsoft.com/.default"

SCOPES = (
    "User.Read.All",
    "Group.Read.All",
    "Directory.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "Application.Read.All",
    "RoleManagement.Read.Directory",
)

# Entra's built-in directory role template IDs that confer meaningful privilege.
PRIVILEGED_ROLE_TEMPLATES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
}

STRONG_METHODS = {
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
    "#microsoft.graph.softwareOathAuthenticationMethod",
    "#microsoft.graph.x509CertificateAuthenticationMethod",
}
WEAK_METHODS = {
    "#microsoft.graph.phoneAuthenticationMethod",
    "#microsoft.graph.emailAuthenticationMethod",
}


@register(
    key="entra",
    label="Microsoft Entra ID",
    vendor="Microsoft",
    scopes=SCOPES,
    description="Identity inventory and authentication posture from Microsoft Graph (read-only).",
)
def fetch(creds: dict) -> ConnectorResult:
    result = ConnectorResult()
    token = oauth_token(creds["tenant_id"], creds["client_id"], creds["client_secret"], SCOPE)

    _organization(token, result)
    privileged = _privileged_roles(token, result)
    _users(token, result, privileged)
    _conditional_access(token, result)
    _authorization_policy(token, result)
    _applications(token, result)

    return result


# ---------------------------------------------------------------------------


def _organization(token: str, result: ConnectorResult) -> None:
    orgs = get_paged(f"{GRAPH}/organization", token, result)
    for o in orgs:
        subject = f"tenant:{o.get('id')}"
        result.observe(subject, "tenant.display_name", o.get("displayName"))
        result.observe(subject, "tenant.country", o.get("countryLetterCode"))
        result.observe(
            subject,
            "tenant.verified_domains",
            [d.get("name") for d in (o.get("verifiedDomains") or [])],
        )
        result.observe(
            subject,
            "tenant.on_premises_sync_enabled",
            bool(o.get("onPremisesSyncEnabled")),
        )


def _privileged_roles(token: str, result: ConnectorResult) -> dict:
    """Returns {user_id: [role names]} for users holding privileged roles."""
    holders: dict = {}
    roles = get_paged(f"{GRAPH}/directoryRoles", token, result)
    for role in roles:
        template = (role.get("roleTemplateId") or "").lower()
        name = role.get("displayName") or template
        if template not in PRIVILEGED_ROLE_TEMPLATES:
            continue
        members = get_paged(f"{GRAPH}/directoryRoles/{role['id']}/members", token, result)
        member_ids = []
        for m in members:
            mid = m.get("id")
            if not mid:
                continue
            member_ids.append(mid)
            holders.setdefault(mid, []).append(name)

        subject = f"role:{template}"
        result.observe(subject, "directory_role.name", name)
        result.observe(subject, "directory_role.member_count", len(member_ids))
        result.observe(subject, "directory_role.is_privileged", True)

    # A tenant with one Global Admin has no break-glass path; with many it has
    # an uncontrolled one. Both are findings, so the count is recorded as a
    # first-class fact rather than derived at check time.
    ga_count = sum(1 for roles_ in holders.values() if "Global Administrator" in roles_)
    result.observe("tenant:current", "tenant.global_admin_count", ga_count)
    return holders


def _users(token: str, result: ConnectorResult, privileged: dict) -> None:
    fields = (
        "id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,"
        "signInActivity,onPremisesSyncEnabled,mail"
    )
    # signInActivity is only exposed on the beta surface for many tenants.
    users = get_paged(
        f"{GRAPH_BETA}/users", token, result, params={"$select": fields, "$top": "999"}
    )

    for u in users:
        uid = u.get("id")
        if not uid:
            continue
        upn = (u.get("userPrincipalName") or "").lower()
        subject = f"user:{uid}"
        roles = privileged.get(uid, [])

        result.observe(subject, "user.upn", upn)
        result.observe(subject, "user.display_name", u.get("displayName"))
        result.observe(subject, "user.enabled", bool(u.get("accountEnabled")))
        result.observe(subject, "user.type", u.get("userType") or "Member")
        result.observe(subject, "user.created", u.get("createdDateTime"))
        result.observe(subject, "user.is_privileged", bool(roles))
        result.observe(subject, "user.privileged_roles", roles)
        result.observe(subject, "user.hybrid_synced", bool(u.get("onPremisesSyncEnabled")))

        activity = u.get("signInActivity") or {}
        last = activity.get("lastSuccessfulSignInDateTime") or activity.get("lastSignInDateTime")
        result.observe(subject, "user.last_sign_in", last)

        result.asset(
            "Identity",
            u.get("displayName") or upn or uid,
            [
                {"identifier_type": "entra_object_id", "identifier_value": uid},
                {"identifier_type": "upn", "identifier_value": upn},
                {"identifier_type": "mail", "identifier_value": u.get("mail") or ""},
            ],
        )

        _auth_methods(token, result, uid, subject)


def _auth_methods(token: str, result: ConnectorResult, uid: str, subject: str) -> None:
    """
    Reduce a user's registered methods to kinds only.

    The raw response contains phone numbers and device display names. Those are
    personal data with no assessment value: the control asks whether a strong
    second factor is registered, not which handset it is on.
    """
    try:
        methods = get_paged(
            f"{GRAPH}/users/{uid}/authentication/methods", token, result, max_pages=3
        )
    except Exception:  # noqa: BLE001 — one user's methods must not stop the run
        result.observe(subject, "user.mfa_readable", False, confidence=40)
        return

    kinds = {m.get("@odata.type") for m in methods if m.get("@odata.type")}
    strong = sorted(k for k in kinds if k in STRONG_METHODS)
    weak = sorted(k for k in kinds if k in WEAK_METHODS)

    result.observe(subject, "user.mfa_readable", True)
    result.observe(subject, "user.mfa_registered", bool(strong or weak))
    result.observe(subject, "user.mfa_strong_registered", bool(strong))
    result.observe(subject, "user.mfa_method_kinds", [k.rsplit(".", 1)[-1] for k in sorted(kinds)])
    result.observe(subject, "user.mfa_method_count", len(kinds))


def _conditional_access(token: str, result: ConnectorResult) -> None:
    policies = get_paged(f"{GRAPH}/identity/conditionalAccess/policies", token, result)
    enabled = [p for p in policies if (p.get("state") or "").lower() == "enabled"]

    result.observe("tenant:current", "ca.policy_count", len(policies))
    result.observe("tenant:current", "ca.enabled_policy_count", len(enabled))

    blocks_legacy = False
    requires_mfa_for_admins = False

    for p in policies:
        pid = p.get("id")
        subject = f"ca_policy:{pid}"
        state = (p.get("state") or "").lower()
        conditions = p.get("conditions") or {}
        grant = p.get("grantControls") or {}
        built_in = [c.lower() for c in (grant.get("builtInControls") or [])]
        client_apps = [c.lower() for c in (conditions.get("clientAppTypes") or [])]

        result.observe(subject, "ca.display_name", p.get("displayName"))
        result.observe(subject, "ca.state", state)
        result.observe(subject, "ca.grant_controls", built_in)
        result.observe(subject, "ca.client_app_types", client_apps)

        if state != "enabled":
            continue
        if "block" in built_in and any(
            c in client_apps for c in ("exchangeactivesync", "other")
        ):
            blocks_legacy = True
        if "mfa" in built_in:
            roles = (conditions.get("users") or {}).get("includeRoles") or []
            if roles or "all" in [
                str(x).lower() for x in ((conditions.get("users") or {}).get("includeUsers") or [])
            ]:
                requires_mfa_for_admins = True

    result.observe("tenant:current", "ca.blocks_legacy_authentication", blocks_legacy)
    result.observe("tenant:current", "ca.requires_mfa_for_privileged", requires_mfa_for_admins)


def _authorization_policy(token: str, result: ConnectorResult) -> None:
    policies = get_paged(f"{GRAPH}/policies/authorizationPolicy", token, result, max_pages=2)
    for p in policies:
        subject = "tenant:current"
        default_perms = p.get("defaultUserRolePermissions") or {}
        result.observe(
            subject,
            "policy.users_can_register_applications",
            bool(default_perms.get("allowedToCreateApps")),
        )
        result.observe(
            subject,
            "policy.users_can_create_security_groups",
            bool(default_perms.get("allowedToCreateSecurityGroups")),
        )
        result.observe(
            subject,
            "policy.guest_invite_setting",
            p.get("allowInvitesFrom"),
        )
        result.observe(
            subject,
            "policy.guest_user_role_id",
            p.get("guestUserRoleId"),
        )


def _applications(token: str, result: ConnectorResult) -> None:
    """
    Enterprise applications and their credential expiry.

    Expired or long-lived app secrets are one of the most reliably present
    findings in any tenant and map cleanly onto ISO A.5.17 and ECC 2-2. Only
    metadata is collected: end dates and hints, never the credential itself.
    """
    apps = get_paged(
        f"{GRAPH}/applications",
        token,
        result,
        params={"$select": "id,appId,displayName,passwordCredentials,keyCredentials,signInAudience"},
    )
    for a in apps:
        subject = f"app:{a.get('id')}"
        pw = a.get("passwordCredentials") or []
        keys = a.get("keyCredentials") or []

        result.observe(subject, "app.display_name", a.get("displayName"))
        result.observe(subject, "app.sign_in_audience", a.get("signInAudience"))
        result.observe(subject, "app.secret_count", len(pw))
        result.observe(subject, "app.certificate_count", len(keys))

        ends = [c.get("endDateTime") for c in (pw + keys) if c.get("endDateTime")]
        result.observe(subject, "app.credential_earliest_expiry", min(ends) if ends else None)
        result.observe(subject, "app.credential_latest_expiry", max(ends) if ends else None)
        result.observe(
            subject,
            "app.multi_tenant",
            (a.get("signInAudience") or "") not in ("AzureADMyOrg", ""),
        )
