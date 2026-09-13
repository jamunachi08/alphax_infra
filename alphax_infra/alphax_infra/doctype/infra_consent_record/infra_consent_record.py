# Copyright (c) 2026, Neotec Integrated Solutions
"""Consent is the legal spine of the whole product: it is what separates
authorised assessment from unauthorised scanning. The exact wording shown at
the time is hashed so it can be proven later."""

import hashlib

import frappe
from frappe.model.document import Document
from frappe.utils import now_datetime


class InfraConsentRecord(Document):
    def before_insert(self):
        self.granted_on = now_datetime()
        try:
            self.source_ip = frappe.local.request_ip
        except Exception:  # noqa: BLE001
            pass

    def validate(self):
        if self.consent_text:
            self.consent_text_hash = hashlib.sha256(
                self.consent_text.strip().encode("utf-8")
            ).hexdigest()

        if self.revoked_on:
            self.status = "Revoked"
        elif self.valid_until and self.valid_until < now_datetime():
            self.status = "Expired"

    def on_update(self):
        """Revoking consent stops collection immediately, on every connector
        that relied on it. Anything else would make the record decorative."""
        if self.status in ("Revoked", "Expired"):
            affected = frappe.get_all(
                "Infra Connector",
                filters={"consent_reference": self.name, "enabled": 1},
                pluck="name",
            )
            for name in affected:
                frappe.db.set_value(
                    "Infra Connector", name,
                    {"enabled": 0, "status": "Revoked",
                     "last_error": f"Consent {self.name} is {self.status}."},
                    update_modified=False,
                )
