# Copyright (c) 2026, Neotec Integrated Solutions
"""Discovered asset. Identifier normalisation and confidence are recomputed on
every save so a hand-edited record is scored by exactly the same rule as a
machine-created one."""

import frappe
from frappe import _
from frappe.model.document import Document

from alphax_infra.core import correlation


class InfraAsset(Document):
    def validate(self):
        self._normalise_identifiers()
        self.confidence = correlation.confidence_for(
            [
                {"identifier_type": i.identifier_type, "identifier_value": i.identifier_value}
                for i in (self.identifiers or [])
            ]
        )
        self._guard_merge_cycle()

    def _normalise_identifiers(self):
        seen = set()
        keep = []
        for row in self.identifiers or []:
            norm = correlation.normalise(row.identifier_type, row.identifier_value)
            if not norm:
                # Placeholder serials and blank values are dropped rather than
                # stored, because a fleet sharing "To Be Filled By O.E.M."
                # would otherwise merge into a single asset.
                continue
            key = (row.identifier_type, norm)
            if key in seen:
                continue
            seen.add(key)
            row.normalised_value = norm
            keep.append(row)
        self.identifiers = keep

    def _guard_merge_cycle(self):
        if not self.merged_into:
            return
        if self.merged_into == self.name:
            frappe.throw(_("An asset cannot be merged into itself."))
        seen = {self.name}
        cursor = self.merged_into
        while cursor:
            if cursor in seen:
                frappe.throw(_("This merge would create a loop."))
            seen.add(cursor)
            cursor = frappe.db.get_value("Infra Asset", cursor, "merged_into")

    def on_update(self):
        if self.lifecycle_state == "Confirmed" and not self.grc_asset:
            from alphax_infra.core.grc_bridge import sync_asset_inventory

            sync_asset_inventory(self.name)
