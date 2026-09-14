# Copyright (c) 2026, Neotec Integrated Solutions
"""Connector configuration. The only place in the app that holds a customer
credential, and it holds it in Frappe's encrypted password store."""

import frappe
from frappe import _
from frappe.model.document import Document

from alphax_infra.connectors import base as connectors


class InfraConnector(Document):
    def validate(self):
        spec = connectors.get(self.connector_type)
        if not spec:
            frappe.throw(_("Unknown connector type: {0}").format(self.connector_type))

        self.requested_scopes = "\n".join(spec.scopes)
        self._seed_scope_rows(spec)
        self._require_consent_before_enabling()

    def _seed_scope_rows(self, spec):
        existing = {r.scope for r in (self.scopes or [])}
        for scope in spec.scopes:
            if scope not in existing:
                self.append("scopes", {"scope": scope, "purpose": spec.description})

    def _require_consent_before_enabling(self):
        """Consent before collection. Enforced, not documented."""
        if not self.enabled:
            return
        if not self.consent_reference:
            frappe.throw(
                _("A connector cannot be enabled without a linked consent record. "
                  "Nothing is collected until an authorised customer contact approves the scope.")
            )
        status = frappe.db.get_value("Infra Consent Record", self.consent_reference, "status")
        if status != "Active":
            frappe.throw(_("The linked consent record is {0}, not Active.").format(status))
        if self.auth_mode == "Admin Consent":
            # Microsoft rendered the authoritative permission list and a Global
            # Administrator accepted it. Re-gating each scope here would be a
            # second approval of something already approved by the only party
            # entitled to approve it.
            return

        unapproved = [r.scope for r in (self.scopes or []) if not r.approved]
        if unapproved:
            frappe.throw(
                _("These scopes have not been approved: {0}").format(", ".join(unapproved))
            )


@frappe.whitelist()
def test_connection(connector: str):
    """Authenticate only. Fetches nothing and stores nothing."""
    from alphax_infra.core.tenancy import require_client

    doc = frappe.get_doc("Infra Connector", connector)
    require_client(doc.client)
    frappe.has_permission("Infra Connector", "write", doc=doc, throw=True)

    spec = connectors.get(doc.connector_type)
    if not spec:
        return {"ok": False, "error": "unknown connector type"}
    try:
        creds = connectors.credentials(connector)
        if not creds.get("client_secret"):
            return {"ok": False, "error": "no credential configured"}
        connectors.oauth_token(
            creds["tenant_id"], creds["client_id"], creds["client_secret"],
            "https://graph.microsoft.com/.default"
            if doc.connector_type in ("entra", "m365")
            else "https://management.azure.com/.default",
        )
        return {"ok": True, "message": "Authenticated. Scopes are verified on the first real run."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}
