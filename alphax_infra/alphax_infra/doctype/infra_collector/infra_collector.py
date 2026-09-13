# Copyright (c) 2026, Neotec Integrated Solutions
"""Collector identity.

The fingerprint carries no unique index: Frappe writes an unset Data field as
an empty string rather than NULL, so a unique index rejects the second
collector created before either has enrolled. Uniqueness is enforced here,
where "set and already taken" can be told apart from "not enrolled yet"."""

import frappe
from frappe import _
from frappe.model.document import Document


class InfraCollector(Document):
    def validate(self):
        if not self.fingerprint:
            return
        clash = frappe.db.get_value(
            "Infra Collector",
            {"fingerprint": self.fingerprint, "name": ["!=", self.name]},
            "name",
        )
        if clash:
            frappe.throw(
                _("Collector {0} is already enrolled with this public key. "
                  "Two collectors must not share signing material.").format(clash)
            )
