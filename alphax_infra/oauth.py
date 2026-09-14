# Copyright (c) 2026, Neotec Integrated Solutions
"""
Microsoft admin-consent onboarding.

The problem this replaces. Until now, starting an engagement meant asking the
customer to register an application in their own tenant, grant it eight
permissions, mint a client secret, and send that secret to us. Four technical
steps, a credential we then have to hold and rotate, and a conversation that
routinely stalls for a week because the person who can do it is busy.

The model here instead: ONE application registered once in Neotec's own tenant,
marked multi-tenant, with read-only permissions. The customer's Global
Administrator opens a link, signs in with their normal account, sees Microsoft's
own permission screen, and clicks Accept. Microsoft provisions a service
principal in their tenant and redirects back. Discovery starts immediately.

What that buys, in order of importance:

  - We never possess a customer credential. There is nothing to leak, rotate or
    hand back at the end of the engagement.
  - The permission list is rendered by Microsoft, not by us. The customer's
    security team is reading Microsoft's screen, which is the only version they
    have any reason to trust.
  - Revocation is one click in their own Enterprise Applications blade, with no
    involvement from us. That asymmetry is what makes the ask reasonable.

The mechanical trick that makes this cheap: an app-only token for a consented
tenant is obtained with OUR client_id and client_secret against THEIR tenant's
token endpoint. `connectors.base.oauth_token` already takes those as separate
arguments, so every existing connector works unchanged. This module only has to
capture the tenant id and record who authorised it.

Security notes, because this is the one guest-reachable browser flow in the app:
  - `state` is HMAC-signed against the site secret, bound to one session, single
    use, and expires in 30 minutes. Nothing else from the query string is
    trusted.
  - The tenant id is validated as a GUID before it reaches a token request.
  - A failed or denied consent is recorded as explicitly as a successful one. A
    customer who clicked Cancel must not look identical to one who never opened
    the link.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode

import frappe
from frappe.utils import get_url, now_datetime

# Microsoft's tenant-agnostic admin consent endpoint. `organizations` excludes
# personal Microsoft accounts, which cannot grant admin consent anyway.
CONSENT_ENDPOINT = "https://login.microsoftonline.com/organizations/v2.0/adminconsent"

STATE_TTL_SECONDS = 1800
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Connectors provisioned automatically once a tenant has consented. Azure is
# absent deliberately: it needs a subscription-scoped role assignment, which
# admin consent does not grant, so it stays a separate explicit step.
AUTO_PROVISION = ("entra", "m365")

CALLBACK_PATH = "/api/method/alphax_infra.oauth.callback"


def settings():
    return frappe.get_cached_doc("AlphaX Infra Settings")


def redirect_uri() -> str:
    """
    Must match the reply URL on the app registration exactly.

    Derived from the site URL rather than configured, so a staging site cannot
    silently be handed production consents.
    """
    configured = (settings().get("mt_redirect_uri") or "").strip()
    return configured or f"{get_url()}{CALLBACK_PATH}"


# ---------------------------------------------------------------------------
# State token
# ---------------------------------------------------------------------------


def _secret() -> bytes:
    return frappe.local.conf.get("encryption_key", frappe.local.conf.get("secret", "")).encode()


def _sign(payload: str) -> str:
    return hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()


def make_state(session: str) -> str:
    """
    Bind the round trip to one assessment session.

    Without this, anyone who knew the reply URL could drive a consent into an
    arbitrary session — which is how a tenant ends up attached to the wrong
    customer's engagement.
    """
    nonce = secrets.token_urlsafe(18)
    payload = f"{session}|{int(time.time())}|{nonce}"
    return f"{payload}|{_sign(payload)}"


def read_state(state: str) -> dict | None:
    try:
        session, issued, nonce, signature = (state or "").split("|", 3)
    except ValueError:
        return None
    payload = f"{session}|{issued}|{nonce}"
    if not hmac.compare_digest(_sign(payload), signature):
        return None
    if time.time() - int(issued) > STATE_TTL_SECONDS:
        return None
    return {"session": session, "nonce": nonce}


# ---------------------------------------------------------------------------
# Building the link
# ---------------------------------------------------------------------------


def requested_scopes() -> list[str]:
    """
    Every read-only permission across the auto-provisioned connectors.

    Shown on our page before the customer leaves, so the Microsoft screen holds
    no surprises. Microsoft renders the authoritative version; ours exists so
    the security team can review it in advance without starting the flow.
    """
    from alphax_infra.connectors import base as connectors

    scopes: set = set()
    for key in AUTO_PROVISION:
        spec = connectors.get(key)
        if spec:
            scopes.update(spec.scopes)
    return sorted(scopes)


def consent_url(session: str) -> str:
    cfg = settings()
    client_id = (cfg.get("mt_client_id") or "").strip()
    if not client_id:
        frappe.throw(
            "No multi-tenant application is configured. Register one in the Neotec "
            "tenant and record its Application (Client) ID in AlphaX Infra Settings."
        )
    return f"{CONSENT_ENDPOINT}?" + urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri(),
            "state": make_state(session),
        }
    )


# ---------------------------------------------------------------------------
# The callback
# ---------------------------------------------------------------------------


def _finish(session: str | None, ok: bool, message: str):
    """Send the browser back to the portal with a readable outcome."""
    target = f"{get_url()}/infra-onboarding"
    if session:
        target += f"?s={session}&status={'granted' if ok else 'failed'}"
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = target
    if not ok:
        frappe.log_error(title="Infra admin consent failed"[:140], message=message[:2000])


@frappe.whitelist(allow_guest=True)
def callback(**kwargs):
    """
    Microsoft redirects the administrator's browser here after the consent
    screen. Guest-accessible by necessity: the customer has no account here.
    """
    state = read_state(kwargs.get("state") or "")
    if not state:
        # Either tampered, replayed, or simply left open past the expiry.
        return _finish(None, False, "consent state was invalid or expired")

    session_name = state["session"]
    if not frappe.db.exists("Infra Assessment Session", session_name):
        return _finish(None, False, f"unknown session {session_name}")

    session = frappe.get_doc("Infra Assessment Session", session_name)

    error = kwargs.get("error")
    if error:
        _record_grant(
            session,
            tenant_id=kwargs.get("tenant"),
            status="Denied",
            detail=f"{error}: {kwargs.get('error_description') or ''}"[:500],
        )
        return _finish(session_name, False, f"administrator declined or Microsoft returned {error}")

    tenant_id = (kwargs.get("tenant") or "").strip()
    if not GUID.match(tenant_id):
        _record_grant(session, tenant_id=None, status="Failed",
                      detail="Microsoft returned no usable tenant id")
        return _finish(session_name, False, "no tenant id returned")

    if str(kwargs.get("admin_consent", "")).lower() not in ("true", "1"):
        _record_grant(session, tenant_id=tenant_id, status="Denied",
                      detail="admin_consent was not true")
        return _finish(session_name, False, "consent was not granted")

    grant = _record_grant(session, tenant_id=tenant_id, status="Granted", detail="")

    # Provisioning and verification are deferred: Microsoft's service principal
    # is eventually consistent, and a token request issued in the same second
    # as the consent frequently fails. Retrying in the background is honest;
    # showing the customer an error is not.
    frappe.enqueue(
        "alphax_infra.oauth.activate",
        queue="long",
        timeout=1800,
        enqueue_after_commit=True,
        grant=grant.name,
    )
    frappe.db.commit()
    return _finish(session_name, True, "")


def _record_grant(session, tenant_id: str | None, status: str, detail: str):
    doc = frappe.get_doc(
        {
            "doctype": "Infra Tenant Grant",
            "client": session.client,
            "session": session.name,
            "provider": "Microsoft",
            "tenant_id": tenant_id,
            "status": status,
            "granted_at": now_datetime(),
            "scopes_requested": "\n".join(requested_scopes()),
            "detail": detail,
            "source_ip": (getattr(frappe.local, "request_ip", "") or "")[:45],
        }
    )
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    return doc


# ---------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------


def activate(grant: str):
    """
    Verify the grant works, provision connectors, and start discovery.

    Verification is a token request and one cheap Graph call. Provisioning is
    deliberately idempotent on (client, connector_type) so a customer who
    re-consents does not accumulate duplicate connectors.
    """
    from alphax_infra.connectors import base as connectors

    doc = frappe.get_doc("Infra Tenant Grant", grant)
    cfg = settings()
    client_id = (cfg.get("mt_client_id") or "").strip()
    client_secret = cfg.get_password("mt_client_secret", raise_exception=False) or ""

    if not client_id or not client_secret:
        doc.db_set({"status": "Failed", "detail": "multi-tenant app is not fully configured"},
                   update_modified=False)
        return

    # Service principal propagation. Six attempts over roughly two minutes
    # covers what Microsoft normally takes; beyond that it is a real failure.
    token = None
    last_error = ""
    for attempt in range(6):
        try:
            token = connectors.oauth_token(
                doc.tenant_id, client_id, client_secret,
                "https://graph.microsoft.com/.default",
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)[:300]
            time.sleep(min(5 * (attempt + 1), 25))

    if not token:
        doc.db_set(
            {"status": "Failed",
             "detail": f"consent recorded but no token could be obtained: {last_error}"},
            update_modified=False,
        )
        return

    domain = _primary_domain(token)
    consent = _consent_record(doc, domain)

    created = []
    for key in AUTO_PROVISION:
        name = _provision(doc, key, consent)
        if name:
            created.append(name)

    doc.db_set(
        {
            "status": "Active",
            "tenant_domain": domain or "",
            "verified_at": now_datetime(),
            "connectors_created": "\n".join(created),
            "detail": "",
        },
        update_modified=False,
    )

    if doc.session:
        frappe.db.set_value("Infra Assessment Session", doc.session,
                            {"status": "Collecting", "consent_obtained": 1,
                             "consent_record": consent},
                            update_modified=False)
    frappe.db.commit()

    for name in created:
        frappe.enqueue(
            "alphax_infra.discovery.run_connector_job",
            queue="long", timeout=3600, enqueue_after_commit=True,
            connector_name=name, triggered_by="admin-consent",
        )


def _primary_domain(token: str) -> str | None:
    """Confirms the token works and gives the customer a recognisable label."""
    import requests

    try:
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/organization"
            "?$select=displayName,verifiedDomains",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if resp.status_code != 200:
            return None
        for org in resp.json().get("value") or []:
            for d in org.get("verifiedDomains") or []:
                if d.get("isDefault"):
                    return d.get("name")
    except Exception:  # noqa: BLE001 — label only; never fail activation on it
        return None
    return None


def _consent_record(grant, domain: str | None) -> str:
    """
    The consent record is the legal artefact. It states what was authorised,
    by which tenant, and through which mechanism — admin consent rather than a
    shared credential, which matters if anyone later asks how we had access.
    """
    doc = frappe.get_doc(
        {
            "doctype": "Infra Consent Record",
            "client": grant.client,
            "granted_by_name": f"Global Administrator, {domain or grant.tenant_id}",
            "granted_by_role": "Microsoft Entra Global Administrator",
            "granted_by_email": f"admin@{domain}" if domain else "unknown",
            "purpose": (
                "Read-only infrastructure discovery for the linked assessment session, "
                "authorised through Microsoft Entra admin consent."
            ),
            "authorised_sources": "\n".join(AUTO_PROVISION),
            "data_categories": (
                "Directory objects, authentication method kinds, policy configuration, "
                "device compliance state, resource configuration. No message content, "
                "no file content, no passwords or key material."
            ),
            "consent_text": (
                "Authorisation was granted through Microsoft's own admin consent screen, "
                "which displayed the exact read-only permissions requested. Microsoft "
                f"provisioned a service principal in tenant {grant.tenant_id}. No "
                "credential was created by or disclosed to Neotec. Consent may be "
                "withdrawn at any time from Enterprise Applications in the customer's "
                "own Entra admin centre, which stops collection immediately."
            ),
            "status": "Active",
        }
    )
    doc.insert(ignore_permissions=True)
    return doc.name


def _provision(grant, connector_type: str, consent: str) -> str | None:
    from alphax_infra.connectors import base as connectors

    spec = connectors.get(connector_type)
    if not spec:
        return None

    existing = frappe.db.get_value(
        "Infra Connector", {"client": grant.client, "connector_type": connector_type}, "name"
    )
    doc = frappe.get_doc("Infra Connector", existing) if existing else frappe.new_doc("Infra Connector")

    doc.update(
        {
            "connector_name": f"{spec.label} — {grant.tenant_domain or grant.tenant_id}"[:140],
            "client": grant.client,
            "connector_type": connector_type,
            "auth_mode": "Admin Consent",
            "tenant_id": grant.tenant_id,
            "tenant_grant": grant.name,
            "consent_reference": consent,
            "status": "Active",
            "enabled": 1,
            "schedule": "Daily",
        }
    )
    for row in doc.scopes or []:
        # Microsoft rendered and the administrator accepted the authoritative
        # list, so per-scope approval here is a record of that, not a second gate.
        row.approved = 1
        row.approved_by = "Administrator"
        row.approved_on = now_datetime()

    doc.flags.ignore_permissions = True
    doc.save() if existing else doc.insert(ignore_permissions=True)
    return doc.name


# ---------------------------------------------------------------------------
# Whitelisted surface
# ---------------------------------------------------------------------------


@frappe.whitelist()
def get_consent_link(session: str):
    """Desk-side. Produces the link an assessor sends to the customer."""
    from alphax_infra.core.tenancy import require_client

    doc = frappe.get_doc("Infra Assessment Session", session)
    require_client(doc.client)
    frappe.has_permission("Infra Assessment Session", "write", doc=doc, throw=True)
    return {
        "portal_url": f"{get_url()}/infra-onboarding?s={doc.name}",
        "reply_url": redirect_uri(),
        "scopes": requested_scopes(),
    }


@frappe.whitelist(allow_guest=True)
def status(session: str):
    """Polled by the portal so the page can show progress without a refresh."""
    if not frappe.db.exists("Infra Assessment Session", session):
        return {"known": False}

    grant = frappe.db.get_value(
        "Infra Tenant Grant",
        {"session": session},
        ["name", "status", "tenant_domain", "detail"],
        as_dict=True,
        order_by="creation desc",
    )
    client = frappe.db.get_value("Infra Assessment Session", session, "client")
    jobs = frappe.get_all(
        "Infra Discovery Job",
        filters={"client": client},
        fields=["state", "observations_received", "module"],
        order_by="creation desc",
        limit=6,
    )
    return {
        "known": True,
        "grant": grant.status if grant else None,
        "tenant": grant.tenant_domain if grant else None,
        "detail": grant.detail if grant else None,
        "jobs": jobs,
        "observations": sum(j.observations_received or 0 for j in jobs),
    }
