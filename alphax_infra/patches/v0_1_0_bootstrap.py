# Copyright (c) 2026, Neotec Integrated Solutions
"""v0.1.0 — create the observation table and seed roles and the catalogue on
a site that installed the app before this patch existed. Idempotent."""

import frappe

from alphax_infra.install import setup


def execute():
    setup()
    frappe.db.commit()
