# Copyright (c) 2026, Neotec Integrated Solutions
"""A check is content. Validation happens here so a broken definition is
refused at save time by the person editing it, not discovered at 03:00 by a
scheduled run that silently returned Inconclusive."""

import json

import frappe
from frappe import _
from frappe.model.document import Document

from alphax_infra.core.rules import CheckDefinitionError, validate_definition


class InfraCheck(Document):
    def validate(self):
        self._validate_definition()
        self._bump_version()

    def _validate_definition(self):
        if not self.definition:
            frappe.throw(_("A check must have a definition."))
        try:
            parsed = json.loads(self.definition)
        except (TypeError, ValueError) as exc:
            frappe.throw(_("Definition is not valid JSON: {0}").format(exc))

        problems = validate_definition(parsed)
        if problems:
            frappe.throw(
                _("This check definition cannot be saved:") + "<br>• " + "<br>• ".join(problems)
            )

        # Re-serialise so stored definitions are formatted consistently and
        # diffs between versions are readable.
        self.definition = json.dumps(parsed, indent=2, sort_keys=True)

    def _bump_version(self):
        if self.is_new():
            self.definition_version = 1
            return
        before = self.get_doc_before_save()
        if before and before.definition != self.definition:
            self.definition_version = (self.definition_version or 1) + 1

    def parsed_definition(self) -> dict:
        return json.loads(self.definition)


@frappe.whitelist()
def run_now(check: str, client: str, as_of: str | None = None):
    """Evaluate one check on demand from the desk."""
    from alphax_infra.core.tenancy import require_client
    from alphax_infra.evaluate import evaluate_check

    client = require_client(client)
    frappe.has_permission("Infra Check", "read", doc=check, throw=True)
    return evaluate_check(check, client, as_of=as_of)
