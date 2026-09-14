# Copyright (c) 2026, Neotec Integrated Solutions
"""
Tenant scope enforcement.

The commercial position is that shared-site tenancy is the standard SKU and a
dedicated site is the regulated SKU. That only holds if shared-site isolation
is actually enforced, and Frappe's User Permissions alone do not enforce it:
they govern the ORM, and they do not follow you into raw SQL, background jobs,
report queries or file downloads. Every place this app leaves the ORM is
exactly where a cross-tenant leak would happen.

So: every whitelisted method, every scheduled job and every raw query in this
app resolves its client through `require_client()`. There is no code path that
takes a client id from the request and trusts it.

`System Manager` is deliberately not a bypass. On a consulting site the
platform administrator maintains the system; that is not the same as being
authorised to read a bank's firewall topology. Cross-tenant read requires the
explicit `Infra Cross Tenant` role, and every use of it is logged.
"""

from __future__ import annotations

import frappe
from frappe import _

CLIENT_DOCTYPE = "GRC Client Profile"
CROSS_TENANT_ROLE = "Infra Cross Tenant"


def allowed_clients(user: str | None = None) -> list[str]:
    """
    The clients this user may see. Empty list means none; the sentinel
    ["*"] means unrestricted (cross-tenant role only).
    """
    user = user or frappe.session.user

    if user == "Administrator":
        return ["*"]
    if CROSS_TENANT_ROLE in frappe.get_roles(user):
        return ["*"]

    perms = frappe.get_all(
        "User Permission",
        filters={"user": user, "allow": CLIENT_DOCTYPE},
        pluck="for_value",
    )
    return sorted(set(perms))


def has_access(client: str, user: str | None = None) -> bool:
    allowed = allowed_clients(user)
    return allowed == ["*"] or client in allowed


def require_client(client: str | None, user: str | None = None) -> str:
    """
    Resolve and authorise a client for the current request.

    If the caller supplies one, it is checked. If not, and the user is scoped
    to exactly one client, that one is used. An unscoped user with no explicit
    client is refused rather than defaulted, because defaulting to "all" is how
    aggregate counts leak across tenants.
    """
    user = user or frappe.session.user
    allowed = allowed_clients(user)

    if client:
        client = str(client).strip()
        if not frappe.db.exists(CLIENT_DOCTYPE, client):
            frappe.throw(_("Unknown client: {0}").format(client), frappe.DoesNotExistError)
        if allowed != ["*"] and client not in allowed:
            _log_denied(user, client)
            raise frappe.PermissionError(_("You are not permitted to access this client."))
        if allowed == ["*"] and user != "Administrator":
            _log_cross_tenant(user, client)
        return client

    if allowed == ["*"]:
        raise frappe.PermissionError(
            _("A client must be specified. Cross-tenant access cannot be implicit.")
        )
    if len(allowed) == 1:
        return allowed[0]
    if not allowed:
        raise frappe.PermissionError(_("You are not assigned to any client."))
    frappe.throw(_("Several clients are available. Specify which one."), frappe.ValidationError)


def scope_condition(alias: str = "", user: str | None = None) -> tuple[str, dict]:
    """
    SQL fragment + params for raw queries. Returns a condition that is always
    safe to AND into a WHERE clause. An unscoped user gets `1=0`, never `1=1`:
    the failure mode of this function is "sees nothing", not "sees everything".
    """
    prefix = f"`{alias}`." if alias else ""
    allowed = allowed_clients(user)
    if allowed == ["*"]:
        return "1=1", {}
    if not allowed:
        return "1=0", {}
    return f"{prefix}`client` IN %(_scope_clients)s", {"_scope_clients": allowed}


def apply_permission_query(user: str | None = None) -> str:
    """
    Hooked into permission_query_conditions for every client-scoped DocType in
    this app, so list views, reports and exports are filtered by the same rule
    as the API.
    """
    allowed = allowed_clients(user)
    if allowed == ["*"]:
        return ""
    if not allowed:
        return "1=0"
    values = ", ".join(frappe.db.escape(c) for c in allowed)
    return f"`client` in ({values})"


def apply_permission_query_shared(user: str | None = None) -> str:
    """
    Variant for doctypes where a blank client means "applies to every client".

    Only `Infra Check` uses this: the 32 shipped catalogue checks are
    firm-wide and carry no client, so the plain scope query would hide all of
    them from every scoped assessor. Using this on a doctype whose client is
    mandatory would be a leak, so it is applied deliberately per doctype in
    hooks rather than being the default.
    """
    allowed = allowed_clients(user)
    if allowed == ["*"]:
        return ""
    values = ", ".join(frappe.db.escape(c) for c in allowed) if allowed else None
    shared = "ifnull(`client`, '') = ''"
    return shared if not values else f"({shared} or `client` in ({values}))"


def has_doc_permission(doc, user=None, permission_type=None) -> bool:
    """Hooked into has_permission for client-scoped DocTypes."""
    client = getattr(doc, "client", None)
    if not client:
        return True
    return has_access(client, user)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def _log_denied(user: str, client: str) -> None:
    frappe.log_error(
        title=f"Infra tenant access denied: {user}"[:140],
        message=f"user={user}\nclient={client}\nmethod={frappe.local.form_dict.get('cmd')}",
    )


def _log_cross_tenant(user: str, client: str) -> None:
    """A cross-tenant read is legitimate but must never be silent."""
    try:
        frappe.get_doc(
            {
                "doctype": "Infra Access Log",
                "user": user,
                "client": client,
                "action": "Cross-tenant read",
                "method": str(frappe.local.form_dict.get("cmd") or "")[:140],
            }
        ).insert(ignore_permissions=True)
    except Exception:  # noqa: BLE001 — logging must never break the request
        frappe.log_error(
            title="Infra cross-tenant log write failed"[:140],
            message=frappe.get_traceback(),
        )
