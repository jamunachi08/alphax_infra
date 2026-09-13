# Copyright (c) 2026, Neotec Integrated Solutions
"""
Install and migrate hooks.

Everything here is idempotent and safe to re-run. `after_migrate` runs the same
code as `after_install`, so a site that upgrades gets the same state as a site
that installs fresh, and there is no "works on a new site only" class of bug.

Seeding follows one rule: create what is missing, never overwrite what exists.
A consultant who tuned a check threshold for a client keeps that tuning through
every subsequent migration. Catalogue updates that genuinely must land on
existing sites go through a versioned patch, where the intent is explicit.
"""

from __future__ import annotations

import json
import os

import frappe

from alphax_infra.core import observations as obs

ROLES = [
    ("Infra Admin", "Configures connectors, collectors and consent. Holds credentials."),
    ("Infra Assessor", "Runs discovery, reviews assets and findings within assigned clients."),
    ("Infra Viewer", "Reads approved results. No configuration access."),
    ("Infra Cross Tenant", "Reads across all clients. Every use is logged."),
]


def before_install():
    """
    `alphax_grc` is a hard dependency, not a soft integration.

    Roles are created here rather than in after_install because DocType sync
    runs between the two, and every doctype JSON in this app carries permission
    rows referencing Infra Admin / Assessor / Viewer. Creating the roles after
    the sync leaves that ordering to chance.
    """
    if "alphax_grc" not in frappe.get_installed_apps():
        frappe.throw(
            "AlphaX Infra requires AlphaX GRC on the same site. It reuses the GRC "
            "control library, evidence model and client register rather than "
            "maintaining a second copy.\n\n"
            "Install it first:  bench --site <site> install-app alphax_grc"
        )
    _create_roles()
    frappe.db.commit()


def after_install():
    setup()


def after_migrate():
    setup()


def setup():
    obs.ensure_table()
    _create_roles()
    _seed_settings()
    _seed_checks()
    frappe.db.commit()


# ---------------------------------------------------------------------------


def _create_roles():
    for name, description in ROLES:
        if frappe.db.exists("Role", name):
            continue
        frappe.get_doc(
            {
                "doctype": "Role",
                "role_name": name,
                "desk_access": 1,
                "description": description,
            }
        ).insert(ignore_permissions=True)


def _seed_settings():
    """
    Materialise the Single with its declared defaults.

    Deliberately not `frappe.db.exists(...)`: for a Single doctype there is no
    row keyed by name to look for — the values live in `tabSingles` — and that
    call does not mean what it appears to mean. Checking the Singles table
    directly is the honest test.

    This matters beyond tidiness. Until the defaults are written, every
    `settings.enabled` read returns a falsy value and the whole module behaves
    as though it were switched off.
    """
    written = frappe.db.sql(
        "SELECT 1 FROM `tabSingles` WHERE `doctype` = %s LIMIT 1",
        ("AlphaX Infra Settings",),
    )
    if written:
        return
    doc = frappe.new_doc("AlphaX Infra Settings")  # applies field defaults
    doc.flags.ignore_permissions = True
    doc.save()


def _catalog_path() -> str:
    return os.path.join(os.path.dirname(__file__), "data", "check_catalog.json")


def _seed_checks() -> dict:
    """
    Load the shipped check catalogue.

    Existing checks are left alone in full, including their definition. A site
    that has tuned CLD-011's approved region list to match a customer's actual
    contract must not have it reset by a migration.
    """
    path = _catalog_path()
    if not os.path.exists(path):
        return {"created": 0, "skipped": 0}

    with open(path, encoding="utf-8") as fh:
        catalog = json.load(fh)

    created = skipped = 0
    for entry in catalog.get("checks", []):
        code = entry.get("check_code")
        if not code:
            continue
        if frappe.db.exists("Infra Check", code):
            skipped += 1
            continue
        try:
            doc = frappe.new_doc("Infra Check")
            doc.update(
                {
                    "check_code": code,
                    "check_name": entry["check_name"],
                    "source": entry.get("source"),
                    "severity": entry.get("severity", "Medium"),
                    "framework": entry.get("framework"),
                    "control": entry.get("control"),
                    "ecc_reference": entry.get("ecc_reference"),
                    "description": entry.get("description"),
                    "remediation": entry.get("remediation"),
                    "auto_create_finding": entry.get("auto_create_finding", 1),
                    "write_evidence": 1,
                    "evaluate_daily": 1,
                    "is_active": entry.get("is_active", 1),
                    "definition": json.dumps(entry["definition"], indent=2, sort_keys=True),
                    "applicability_note": (
                        "Mapped by control identifier. A mapping proposes evidence reuse; "
                        "it does not prove the target control. Confirm scope and sampling "
                        "before relying on it."
                    ),
                }
            )
            doc.insert(ignore_permissions=True)
            created += 1
        except Exception:  # noqa: BLE001 — one bad entry must not abort install
            frappe.log_error(
                title=f"Infra check seed failed: {code}"[:140], message=frappe.get_traceback()
            )

    return {"created": created, "skipped": skipped}


@frappe.whitelist()
def reseed_catalog():
    """Manual re-run for a site that was installed before a catalogue update."""
    frappe.only_for("System Manager")
    out = _seed_checks()
    frappe.db.commit()
    return out
