# Copyright (c) 2026, Neotec Integrated Solutions
"""A tenant's admin-consent grant.

Revoking here is a record of a revocation that happened in the customer's own
Entra admin centre, or an instruction to stop using one that still exists. It
disables the dependent connectors either way, because continuing to collect
against a grant somebody asked us to stop using is the failure that ends an
engagement."""

import frappe
from frappe.model.document import Document
from frappe.utils import now_datetime


class InfraTenantGrant(Document):
    def on_update(self):
        if self.status != "Revoked":
            return
        if not self.revoked_at:
            self.db_set("revoked_at", now_datetime(), update_modified=False)
        for name in frappe.get_all(
            "Infra Connector", filters={"tenant_grant": self.name}, pluck="name"
        ):
            frappe.db.set_value(
                "Infra Connector", name,
                {"enabled": 0, "status": "Revoked",
                 "last_error": f"Tenant grant {self.name} was revoked."},
                update_modified=False,
            )
