# Copyright (c) 2026, Neotec Integrated Solutions
"""
Assessment session and the invitation link.

The specification is right that a link cannot inspect an internal network, and
this module is where that honesty is enforced in the product rather than
promised in a sales deck. Opening an invitation shows the customer exactly
which sources will be read and what each one collects, and records a named
person's consent before anything runs.

Only the hash of the invitation token is stored. A database dump does not
yield a working link, and an expired session has its hash cleared rather than
merely its status changed.
"""

from __future__ import annotations

import hashlib
import secrets

import frappe
from frappe.utils import add_days, get_url, now_datetime

from alphax_infra.connectors import base as connectors
from alphax_infra.core.tenancy import require_client

CONSENT_TEXT = (
    "I confirm that I am authorised to approve this assessment on behalf of the "
    "organisation named above. I understand that the sources listed will be read "
    "using read-only access, that no passwords, private keys or packet contents "
    "are collected, and that this authorisation may be withdrawn at any time, "
    "which stops collection immediately."
)


@frappe.whitelist()
def create_invitation(session: str, email: str, valid_days: int = 14):
    doc = frappe.get_doc("Infra Assessment Session", session)
    require_client(doc.client)
    frappe.has_permission("Infra Assessment Session", "write", doc=doc, throw=True)

    token = f"{doc.name}.{secrets.token_urlsafe(32)}"
    doc.db_set(
        {
            "invitation_token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "invited_email": email,
            "invited_on": now_datetime(),
            "expires_on": add_days(now_datetime(), int(valid_days)),
            "status": "Invited",
        },
        update_modified=False,
    )
    site = get_url()
    return {
        "url": f"{site}/infra-assessment?t={token}",
        "expires": str(doc.expires_on),
        "notice": "The link is shown once. Reissue if it is lost.",
    }


def _resolve(token: str):
    """Resolve a token to a live session, or None."""
    if not token or "." not in token:
        return None
    name = token.split(".", 1)[0]
    row = frappe.db.get_value(
        "Infra Assessment Session",
        name,
        ["name", "client", "status", "invitation_token_hash", "expires_on"],
        as_dict=True,
    )
    if not row or not row.invitation_token_hash:
        return None
    if not secrets.compare_digest(
        row.invitation_token_hash, hashlib.sha256(token.encode()).hexdigest()
    ):
        return None
    if row.expires_on and row.expires_on < now_datetime():
        return None
    return row


@frappe.whitelist(allow_guest=True)
def describe(token: str):
    """
    What the customer sees before consenting.

    Returns the scope and, for each configured connector, the exact read-only
    permissions that will be requested. Showing the permission list before the
    consent button is the difference between informed authorisation and a
    tick-box.
    """
    session = _resolve(token)
    if not session:
        frappe.local.response["http_status_code"] = 404
        return {"valid": False}

    doc = frappe.get_doc("Infra Assessment Session", session.name)
    configured = frappe.get_all(
        "Infra Connector",
        filters={"client": session.client},
        fields=["connector_type", "connector_name"],
    )

    sources = []
    for c in configured:
        spec = connectors.get(c.connector_type)
        sources.append(
            {
                "name": c.connector_name,
                "vendor": spec.vendor if spec else c.connector_type,
                "label": spec.label if spec else c.connector_type,
                "permissions": list(spec.scopes) if spec else [],
                "what_it_reads": spec.description if spec else "",
            }
        )

    return {
        "valid": True,
        "organisation": frappe.db.get_value("GRC Client Profile", session.client, "client_name"),
        "title": doc.session_title,
        "purpose": doc.purpose,
        "frameworks": (doc.frameworks or "").splitlines(),
        "scope_summary": doc.scope_summary,
        "exclusions": doc.exclusions,
        "sources": sources,
        "not_collected": [
            "Passwords, password hashes and private keys",
            "VPN pre-shared keys and certificate private material",
            "Packet contents or network traffic",
            "Mailbox, file or document contents",
            "Personal data beyond the account identifiers needed to test access controls",
        ],
        "consent_text": CONSENT_TEXT,
        "expires_on": str(session.expires_on),
        "status": session.status,
    }


@frappe.whitelist(allow_guest=True)
def consent(token: str, name: str, role: str, email: str, agreed: int = 0):
    """Record named consent. Nothing collects until this succeeds."""
    session = _resolve(token)
    if not session:
        frappe.local.response["http_status_code"] = 404
        return {"ok": False, "reason": "invitation is invalid or expired"}

    if not int(agreed or 0):
        frappe.local.response["http_status_code"] = 400
        return {"ok": False, "reason": "consent was not given"}

    for field, value in (("name", name), ("role", role), ("email", email)):
        if not (value or "").strip():
            frappe.local.response["http_status_code"] = 400
            return {"ok": False, "reason": f"{field} is required"}

    doc = frappe.get_doc("Infra Assessment Session", session.name)
    sources = frappe.get_all(
        "Infra Connector", filters={"client": session.client}, pluck="connector_name"
    )

    record = frappe.get_doc(
        {
            "doctype": "Infra Consent Record",
            "client": session.client,
            "granted_by_name": name,
            "granted_by_role": role,
            "granted_by_email": email,
            "purpose": f"{doc.purpose} — {doc.session_title}",
            "authorised_sources": "\n".join(sources),
            "consent_text": CONSENT_TEXT,
            "status": "Active",
            "valid_until": doc.expires_on,
        }
    ).insert(ignore_permissions=True)

    doc.db_set(
        {"consent_record": record.name, "consent_obtained": 1, "status": "Consented"},
        update_modified=False,
    )
    frappe.db.commit()

    return {
        "ok": True,
        "consent_record": record.name,
        "note": "Consent recorded. Connectors must still be linked to this record and "
                "enabled by the assessment team before any collection begins.",
    }
