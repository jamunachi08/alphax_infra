# Copyright (c) 2026, Neotec Integrated Solutions
"""
v0.1.1 — carry `Infra Check Result.check` over to `infra_check`.

`check` is a MariaDB reserved word. Frappe quotes its own DDL so the column was
created without complaint, but every hand-written query referencing `r.check`
was a syntax error waiting for the first evaluation run. The field is renamed;
this moves any rows a v0.1.0 site had already written.

Frappe's migrate adds the new column and leaves the old one in place, so this
patch copies across and then drops the orphan. Idempotent: it inspects the
live schema rather than assuming which columns exist.
"""

import frappe

TABLE = "tabInfra Check Result"


def _columns() -> set:
    return {
        r[0]
        for r in frappe.db.sql(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
            (TABLE,),
        )
    }


def execute():
    if not frappe.db.table_exists("Infra Check Result"):
        return

    cols = _columns()
    if "check" not in cols:
        return  # fresh install, or already migrated

    if "infra_check" in cols:
        frappe.db.sql(
            f"UPDATE `{TABLE}` SET `infra_check` = `check` "
            f"WHERE (`infra_check` IS NULL OR `infra_check` = '') "
            f"AND `check` IS NOT NULL AND `check` != ''"
        )
        frappe.db.sql(f"ALTER TABLE `{TABLE}` DROP COLUMN `check`")
        frappe.db.commit()
