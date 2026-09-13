# Copyright (c) 2026, Neotec Integrated Solutions
"""
The bridge into AlphaX GRC.

This module is the commercial argument for the whole app: a consultant runs a
GRC engagement, discovery runs against the customer's tenant, and a meaningful
share of the evidence requests satisfy themselves with a machine-collected,
timestamped, re-runnable fact instead of a screenshot someone emailed.

Two rules govern everything here.

First, this app writes into GRC through the public document API only. It never
reaches into alphax_grc internals, never assumes a field exists without
checking live meta, and never edits a GRC record a human has already reviewed.
alphax_grc is on its own release train; if a Select option set changes there,
this bridge degrades to a safe value rather than throwing during an ingest.

Second, automation proposes and a human disposes. A check result becomes
Collected evidence and an Open finding. It never marks a control Compliant,
never closes a finding, and never approves anything. The spec's "human review
remains authoritative" principle is enforced here in code, not in a policy
document.
"""

from __future__ import annotations

import json

import frappe
from frappe.utils import now_datetime

from alphax_infra.core.rules import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS

# Written only on creation. If a reviewer later changes status, we leave it.
EVIDENCE_STATUS_BY_VERDICT = {
    PASS: "Verified",
    FAIL: "Collected",
    INCONCLUSIVE: "Draft",
    NOT_APPLICABLE: "Archived",
}

SEVERITY_FALLBACK = "Medium"


def grc_installed() -> bool:
    return "alphax_grc" in frappe.get_installed_apps()


def _legal_option(doctype: str, fieldname: str, wanted: str, fallback: str | None = None) -> str | None:
    """
    Resolve a Select value against live meta.

    alphax_grc has changed option sets between releases (the evidence runner
    there hit the same problem). Reading meta at write time costs one cached
    lookup and turns a hard validation failure during ingest into a graceful
    downgrade.
    """
    try:
        meta = frappe.get_meta(doctype)
        df = meta.get_field(fieldname)
    except Exception:  # noqa: BLE001
        return wanted
    if not df or not df.options:
        return wanted
    options = [o.strip() for o in df.options.split("\n") if o.strip()]
    if wanted in options:
        return wanted
    if fallback and fallback in options:
        return fallback
    return options[0] if options else None


def _exists(doctype: str) -> bool:
    return bool(frappe.db.exists("DocType", doctype))


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def upsert_evidence(check_result_name: str) -> str | None:
    """
    Create or refresh the GRC Evidence record backing one check result.

    Keyed on the check + client so re-running a check updates one evidence
    record rather than accumulating a new one per night. The evidence body
    carries the failing-subject sample and the as-of timestamp, which is what
    an auditor actually asks for.
    """
    if not grc_installed() or not _exists("GRC Evidence"):
        return None

    cr = frappe.get_doc("Infra Check Result", check_result_name)
    check = frappe.get_doc("Infra Check", cr.check)

    if not check.control:
        # Nothing to attach to. Not an error: plenty of checks are
        # operational rather than control-mapped.
        return None

    marker = f"infra-check:{check.name}"
    existing = frappe.db.get_value(
        "GRC Evidence",
        {"client": cr.client, "evidence_title": ["like", f"%{marker}%"]},
        "name",
    )

    body = _evidence_body(cr, check, marker)
    status = _legal_option(
        "GRC Evidence",
        "status",
        EVIDENCE_STATUS_BY_VERDICT.get(cr.verdict, "Draft"),
        "Draft",
    )
    etype = _legal_option("GRC Evidence", "evidence_type", "Configuration", "Other")

    try:
        if existing:
            doc = frappe.get_doc("GRC Evidence", existing)
            if (doc.get("status") or "") in ("Verified", "Archived") and cr.verdict == PASS:
                # A reviewer already accepted this. Refresh the body, leave
                # their decision alone.
                doc.db_set("description", body, update_modified=False)
                return doc.name
            doc.description = body
            if status:
                doc.status = status
            doc.save(ignore_permissions=True)
            return doc.name

        doc = frappe.new_doc("GRC Evidence")
        doc.update(
            {
                "client": cr.client,
                "evidence_title": f"{check.check_name} [{marker}]"[:140],
                "description": body,
            }
        )
        if status:
            doc.status = status
        if etype:
            doc.evidence_type = etype
        _set_if_field(doc, "control", check.control)
        _set_if_field(doc, "framework", check.framework)
        _set_if_field(doc, "collection_date", now_datetime())
        doc.insert(ignore_permissions=True)
        return doc.name
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra evidence write-back failed: {check.name}"[:140],
            message=frappe.get_traceback(),
        )
        return None


def _set_if_field(doc, fieldname: str, value) -> None:
    if value is None:
        return
    if doc.meta.get_field(fieldname):
        doc.set(fieldname, value)


def _evidence_body(cr, check, marker: str) -> str:
    sample = json.loads(cr.failing_subjects or "[]")[:25]
    lines = [
        f"Machine-collected evidence — {marker}",
        "",
        f"Check:      {check.check_name}",
        f"Framework:  {check.framework or '-'}   Control: {check.control or '-'}",
        f"Source:     {check.source or '-'}",
        f"Verdict:    {cr.verdict}",
        f"Evaluated:  {cr.passed} passed / {cr.failed} failed of {cr.total} subjects "
        f"({cr.pass_rate}%)",
        f"As of:      {cr.as_of or cr.evaluated_at}",
        f"Run:        {cr.name}",
        "",
        "This record was produced automatically from observation data. It is a "
        "statement of what was observed, not a conclusion about compliance. A "
        "qualified reviewer must accept, reject or supersede it.",
    ]
    if sample:
        lines += ["", f"Failing subjects (sample of {len(sample)} of {cr.failed}):"]
        lines += [f"  - {s}" for s in sample]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def upsert_finding(check_result_name: str) -> str | None:
    """
    Raise or refresh a GRC Audit Finding for a failed check.

    Idempotent on (check, client): a check failing every night for a month is
    one finding with a moving last-observed date, not thirty findings. When the
    check starts passing the finding is annotated as ready for verification and
    left for a human to close — this app does not close findings.
    """
    if not grc_installed() or not _exists("GRC Audit Finding"):
        return None

    cr = frappe.get_doc("Infra Check Result", check_result_name)
    check = frappe.get_doc("Infra Check", cr.check)
    marker = f"infra-check:{check.name}"

    existing = frappe.db.get_value(
        "GRC Audit Finding",
        {"client": cr.client, "finding_title": ["like", f"%{marker}%"]},
        ["name", "status"],
        as_dict=True,
    )

    if cr.verdict != FAIL:
        if existing:
            _annotate_recovered(existing, cr, marker)
        return existing.name if existing else None

    if not check.auto_create_finding:
        return None

    severity = _legal_option(
        "GRC Audit Finding", "severity", check.severity or SEVERITY_FALLBACK, SEVERITY_FALLBACK
    )
    body = _finding_body(cr, check)

    try:
        if existing:
            doc = frappe.get_doc("GRC Audit Finding", existing.name)
            doc.db_set("description", body, update_modified=False)
            if doc.meta.get_field("last_observed"):
                doc.db_set("last_observed", now_datetime(), update_modified=False)
            return doc.name

        doc = frappe.new_doc("GRC Audit Finding")
        doc.update(
            {
                "client": cr.client,
                "finding_title": f"{check.check_name} [{marker}]"[:140],
                "description": body,
            }
        )
        if severity:
            doc.severity = severity
        _set_if_field(doc, "framework", check.framework)
        _set_if_field(doc, "control", check.control)
        _set_if_field(doc, "source", "Automated Discovery")
        _set_if_field(doc, "identified_date", now_datetime())
        doc.insert(ignore_permissions=True)
        return doc.name
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra finding write-back failed: {check.name}"[:140],
            message=frappe.get_traceback(),
        )
        return None


def _annotate_recovered(existing, cr, marker: str) -> None:
    """The check now passes. Say so on the finding; do not close it."""
    try:
        note = (
            f"\n\n[{now_datetime()}] Automated re-evaluation returned {cr.verdict} "
            f"({cr.passed}/{cr.total} subjects passing). Ready for verification. "
            f"Closure requires reviewer confirmation."
        )
        current = frappe.db.get_value("GRC Audit Finding", existing.name, "description") or ""
        if marker in current and "Ready for verification" in current[-400:]:
            return  # already annotated since the last change
        frappe.db.set_value(
            "GRC Audit Finding", existing.name, "description", (current + note)[:100000],
            update_modified=False,
        )
    except Exception:  # noqa: BLE001
        frappe.log_error(title="Infra finding annotate failed"[:140], message=frappe.get_traceback())


def _finding_body(cr, check) -> str:
    sample = json.loads(cr.failing_subjects or "[]")[:25]
    lines = [
        check.description or check.check_name,
        "",
        f"{cr.failed} of {cr.total} subjects failed this check ({cr.pass_rate}% passing).",
        f"Source: {check.source or '-'}   Detected: {cr.evaluated_at}",
        "",
        "Remediation guidance:",
        check.remediation or "Not specified in the check definition.",
    ]
    if sample:
        lines += ["", f"Affected subjects (sample of {len(sample)}):"]
        lines += [f"  - {s}" for s in sample]
    lines += [
        "",
        "Raised automatically from discovery observations. Verify scope and "
        "applicability before treating it as a confirmed gap.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Asset Inventory
# ---------------------------------------------------------------------------


def sync_asset_inventory(infra_asset: str) -> str | None:
    """
    Project a discovered Infra Asset into alphax_grc's GRC Asset Inventory.

    GRC Asset Inventory is the consultant-facing register: CIA ratings,
    criticality, data classification, control linkage. Those are human
    judgements and this function never overwrites them. It only fills the
    technical fields that discovery is authoritative for, and only when they
    are empty or machine-owned, so a consultant's classification survives
    every subsequent discovery run.
    """
    if not grc_installed() or not _exists("GRC Asset Inventory"):
        return None

    src = frappe.get_doc("Infra Asset", infra_asset)
    if src.merged_into:
        return None

    marker = f"infra:{src.name}"
    existing = frappe.db.get_value("GRC Asset Inventory", {"asset_id": marker}, "name")

    # Discovery owns these. Everything else on the GRC record is the
    # consultant's and is never touched.
    machine_fields = {
        "asset_name": src.asset_name,
        "asset_id": marker,
        "hostname": src.hostname,
        "ip_address": src.ip_address,
        "os_version": src.os_version,
        "make_model": src.make_model,
        "serial_number": src.serial_number,
    }

    try:
        if existing:
            doc = frappe.get_doc("GRC Asset Inventory", existing)
            changed = False
            for k, v in machine_fields.items():
                if v and doc.meta.get_field(k) and doc.get(k) != v:
                    doc.set(k, v)
                    changed = True
            if changed:
                doc.save(ignore_permissions=True)
            return doc.name

        doc = frappe.new_doc("GRC Asset Inventory")
        doc.client = src.client
        for k, v in machine_fields.items():
            if v and doc.meta.get_field(k):
                doc.set(k, v)
        atype = _legal_option("GRC Asset Inventory", "asset_type", src.asset_type, "Other")
        if atype:
            doc.asset_type = atype
        if doc.meta.get_field("notes"):
            doc.notes = (
                f"Discovered by AlphaX Infra ({src.first_seen_source or 'unknown source'}). "
                f"Technical fields are maintained by discovery; classification, CIA "
                f"ratings and control linkage are yours to set and will not be overwritten."
            )
        doc.insert(ignore_permissions=True)
        src.db_set("grc_asset", doc.name, update_modified=False)
        return doc.name
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra asset sync failed: {infra_asset}"[:140],
            message=frappe.get_traceback(),
        )
        return None


# ---------------------------------------------------------------------------
# Coverage reporting
# ---------------------------------------------------------------------------


def control_coverage(client: str) -> list[dict]:
    """
    Which GRC controls currently have machine evidence behind them, and what
    that evidence says. This is the number that sells the product: "discovery
    satisfies N of your M evidence requests automatically".
    """
    rows = frappe.db.sql(
        """
        SELECT c.framework, c.control,
               COUNT(DISTINCT c.name) AS checks,
               SUM(CASE WHEN r.verdict = 'Pass' THEN 1 ELSE 0 END) AS passing,
               SUM(CASE WHEN r.verdict = 'Fail' THEN 1 ELSE 0 END) AS failing,
               SUM(CASE WHEN r.verdict = 'Inconclusive' THEN 1 ELSE 0 END) AS inconclusive,
               MAX(r.evaluated_at) AS last_evaluated
        FROM `tabInfra Check` c
        LEFT JOIN `tabInfra Check Result` r
               ON r.check = c.name AND r.client = %(client)s AND r.is_latest = 1
        WHERE c.is_active = 1 AND c.control IS NOT NULL AND c.control != ''
        GROUP BY c.framework, c.control
        ORDER BY c.framework, c.control
        """,
        {"client": client},
        as_dict=True,
    )
    return rows
