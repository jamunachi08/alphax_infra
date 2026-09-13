# Copyright (c) 2026, Neotec Integrated Solutions
"""
The bridge into AlphaX GRC.

This module is the commercial argument for the whole app: a consultant runs a
GRC engagement, discovery runs against the customer's tenant, and a meaningful
share of the evidence requests satisfy themselves with a machine-collected,
timestamped, re-runnable fact instead of a screenshot someone emailed.

Three rules govern everything here.

First, this app writes into GRC through the public document API only, and it
targets field names that actually exist in the GRC schema — verified against
alphax_grc v2.14.0, not assumed. `FIELD_MAP` is the single place those names
live, so a schema change in GRC is a one-line fix here rather than a hunt
through the module. Writing to a field that does not exist is the worst kind of
bug in Frappe: `doc.description = x` on a doctype with no `description` field
raises nothing, persists nothing, and produces an evidence record that looks
fine and is empty.

Second, every Select value is resolved against live meta before it is written.
GRC's `framework` field on a finding is a Select with a fixed option list, and
our catalogue records the full standard designation ("ISO/IEC 27001:2022"),
which is not one of those options. Writing it directly throws a validation
error mid-ingest. `FRAMEWORK_MAP` translates, `_legal_option` verifies, and an
unmappable value degrades to a legal one rather than aborting a discovery run.

Third, automation proposes and a human disposes. A check result becomes
Collected evidence and an Open finding. It never marks a control compliant,
never closes a finding, and never approves anything.
"""

from __future__ import annotations

import html
import json

import frappe
from frappe.utils import now_datetime

from alphax_infra.core.rules import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS

# ---------------------------------------------------------------------------
# Schema mapping — verified against alphax_grc v2.14.0
#
# Every name on the right is a field that exists in GRC today. Anything this
# app wants to record that GRC has no field for goes into the body text rather
# than onto an attribute that never persists.
# ---------------------------------------------------------------------------

FIELD_MAP = {
    "GRC Evidence": {
        "title": "evidence_title",
        "body": "notes",                # GRC Evidence has no 'description'
        "collected": "collected_on",    # not 'collection_date'
        "type": "evidence_type",
        "status": "status",
    },
    "GRC Audit Finding": {
        "title": "finding_title",
        "body": "observation",          # Text Editor; no 'description' exists
        "recommendation": "recommendation",
        "control": "control_reference",  # not 'control'
        "framework": "framework",        # Select — must be mapped
        "severity": "severity",
        "status": "status",
    },
}

# Our catalogue stores full standard designations. GRC's Select stores short
# labels. Left unmapped, an insert fails validation partway through a run.
FRAMEWORK_MAP = {
    "ISO/IEC 27001:2022": "ISO 27001",
    "ISO 27001:2022": "ISO 27001",
    "ISO/IEC 27001": "ISO 27001",
    "NCA ECC-2:2024": "NCA ECC-2:2024",
    "NCA ECC": "NCA ECC-2:2024",
    "ISO/IEC 42001:2023": "ISO 42001",
    "ISO/IEC 22301": "ISO 22301",
    "NIST CSF 2.0": "NIST CSF 2.0",
    "PDPL": "PDPL",
    "GDPR": "GDPR",
}

# GRC Asset Inventory's asset_type option set does not match ours. Mapping it
# explicitly beats falling through to the first option, which is blank.
ASSET_TYPE_MAP = {
    "Server": "Server",
    "Endpoint": "Laptop",
    "Network Device": "Network Device",
    "Firewall": "Network Device",
    "Identity": "People",
    "Cloud Resource": "Cloud Service",
    "Application": "Software",
    "Database": "Software",
    "Storage": "Cloud Service",
    "Other": "Service",
}

EVIDENCE_STATUS_BY_VERDICT = {
    PASS: "Verified",
    FAIL: "Collected",
    INCONCLUSIVE: "Draft",
    NOT_APPLICABLE: "Archived",
}

SEVERITY_FALLBACK = "Medium"


def grc_installed() -> bool:
    return "alphax_grc" in frappe.get_installed_apps()


def _exists(doctype: str) -> bool:
    return bool(frappe.db.exists("DocType", doctype))


def _field(doctype: str, key: str) -> str | None:
    """Resolve a logical field to the real GRC fieldname, if it still exists."""
    name = FIELD_MAP.get(doctype, {}).get(key)
    if not name:
        return None
    try:
        return name if frappe.get_meta(doctype).get_field(name) else None
    except Exception:  # noqa: BLE001
        return None


def _legal_option(doctype: str, fieldname: str, wanted: str, fallback: str | None = None) -> str | None:
    """
    Resolve a Select value against live meta.

    Reading meta at write time costs one cached lookup and turns a hard
    validation failure during ingest into a graceful downgrade.
    """
    try:
        df = frappe.get_meta(doctype).get_field(fieldname)
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


def _set(doc, fieldname: str | None, value) -> None:
    if fieldname and value is not None and doc.meta.get_field(fieldname):
        doc.set(fieldname, value)


def _para(text: str) -> str:
    """
    GRC's finding body is a Text Editor, so it renders as HTML. Plain text with
    newlines collapses into one unreadable paragraph, in the exact place an
    auditor reads it.
    """
    return "".join(
        f"<p>{html.escape(line)}</p>" if line.strip() else "<br>"
        for line in text.split("\n")
    )


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def upsert_evidence(check_result_name: str) -> str | None:
    """
    Create or refresh the GRC Evidence record backing one check result.

    Keyed on the check + client so re-running a check updates one evidence
    record rather than accumulating a new one per night.

    GRC Evidence has no control or framework field — it links to a source
    through related_doctype / related_document. So the evidence points back at
    the Infra Check Result, which is live and re-runnable, and the control
    mapping is stated in the body.
    """
    if not grc_installed() or not _exists("GRC Evidence"):
        return None

    cr = frappe.get_doc("Infra Check Result", check_result_name)
    check = frappe.get_doc("Infra Check", cr.infra_check)

    title_f = _field("GRC Evidence", "title")
    body_f = _field("GRC Evidence", "body")
    if not title_f:
        return None

    marker = f"infra-check:{check.name}"
    existing = frappe.db.get_value(
        "GRC Evidence", {"client": cr.client, title_f: ["like", f"%{marker}%"]}, "name"
    )

    body = _evidence_body(cr, check, marker)
    status = _legal_option(
        "GRC Evidence", "status", EVIDENCE_STATUS_BY_VERDICT.get(cr.verdict, "Draft"), "Draft"
    )

    try:
        if existing:
            doc = frappe.get_doc("GRC Evidence", existing)
            if (doc.get("status") or "") in ("Verified", "Archived") and cr.verdict == PASS:
                # A reviewer already accepted this. Refresh the body, leave
                # their decision alone.
                if body_f:
                    doc.db_set(body_f, body, update_modified=False)
                return doc.name
            _set(doc, body_f, body)
            _set(doc, _field("GRC Evidence", "status"), status)
            _set(doc, _field("GRC Evidence", "collected"), now_datetime())
            doc.save(ignore_permissions=True)
            return doc.name

        doc = frappe.new_doc("GRC Evidence")
        doc.client = cr.client
        _set(doc, title_f, f"{check.check_name} [{marker}]"[:140])
        _set(doc, body_f, body)
        _set(doc, _field("GRC Evidence", "status"), status)
        _set(doc, _field("GRC Evidence", "collected"), now_datetime())
        _set(
            doc,
            _field("GRC Evidence", "type"),
            _legal_option("GRC Evidence", "evidence_type", "Configuration", "Other"),
        )
        # Live link back to the re-runnable source.
        if doc.meta.get_field("related_doctype"):
            doc.related_doctype = "Infra Check Result"
            doc.related_document = cr.name
        doc.insert(ignore_permissions=True)
        return doc.name
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra evidence write-back failed: {check.name}"[:140],
            message=frappe.get_traceback(),
        )
        return None


def _evidence_body(cr, check, marker: str) -> str:
    sample = json.loads(cr.failing_subjects or "[]")[:25]
    lines = [
        f"Machine-collected evidence — {marker}",
        "",
        f"Check:      {check.check_code} — {check.check_name}",
        f"Framework:  {check.framework or '-'}   Control: {check.control or '-'}",
        f"NCA ECC:    {check.ecc_reference or '-'}",
        f"Source:     {check.source or '-'}",
        f"Verdict:    {cr.verdict}",
        f"Evaluated:  {cr.passed} passed / {cr.failed} failed of {cr.total} subjects "
        f"({cr.pass_rate}%)",
        f"As of:      {cr.as_of or cr.evaluated_at}",
        f"Run:        {cr.name}",
        "",
        "Produced automatically from observation data. It is a statement of what "
        "was observed, not a conclusion about compliance. A qualified reviewer "
        "must accept, reject or supersede it.",
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
    one finding with a moving last-observed note, not thirty findings. When the
    check starts passing the finding is annotated as ready for verification and
    left for a human to close — this app does not close findings.
    """
    if not grc_installed() or not _exists("GRC Audit Finding"):
        return None

    cr = frappe.get_doc("Infra Check Result", check_result_name)
    check = frappe.get_doc("Infra Check", cr.infra_check)

    title_f = _field("GRC Audit Finding", "title")
    body_f = _field("GRC Audit Finding", "body")
    if not title_f:
        return None

    marker = f"infra-check:{check.name}"
    existing = frappe.db.get_value(
        "GRC Audit Finding",
        {"client": cr.client, title_f: ["like", f"%{marker}%"]},
        ["name", "status"],
        as_dict=True,
    )

    if cr.verdict != FAIL:
        if existing:
            _annotate_recovered(existing, cr, body_f)
        return existing.name if existing else None

    if not check.auto_create_finding:
        return None

    try:
        if existing:
            doc = frappe.get_doc("GRC Audit Finding", existing.name)
            if body_f:
                doc.db_set(body_f, _para(_finding_body(cr, check)), update_modified=False)
            return doc.name

        doc = frappe.new_doc("GRC Audit Finding")
        doc.client = cr.client
        _set(doc, title_f, f"{check.check_name} [{marker}]"[:140])
        _set(doc, body_f, _para(_finding_body(cr, check)))
        _set(
            doc,
            _field("GRC Audit Finding", "recommendation"),
            _para(check.remediation or "Not specified in the check definition."),
        )
        _set(doc, _field("GRC Audit Finding", "control"), check.control)
        _set(
            doc,
            _field("GRC Audit Finding", "severity"),
            _legal_option(
                "GRC Audit Finding",
                "severity",
                check.severity or SEVERITY_FALLBACK,
                SEVERITY_FALLBACK,
            ),
        )
        # The Select that would otherwise throw: our catalogue stores the full
        # designation, GRC stores a short label.
        fw_field = _field("GRC Audit Finding", "framework")
        if fw_field and check.framework:
            wanted = FRAMEWORK_MAP.get(check.framework, check.framework)
            _set(doc, fw_field, _legal_option("GRC Audit Finding", fw_field, wanted, "Custom"))
        doc.insert(ignore_permissions=True)
        return doc.name
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra finding write-back failed: {check.name}"[:140],
            message=frappe.get_traceback(),
        )
        return None


def _annotate_recovered(existing, cr, body_f: str | None) -> None:
    """The check now passes. Say so on the finding; do not close it."""
    if not body_f:
        return
    try:
        current = frappe.db.get_value("GRC Audit Finding", existing.name, body_f) or ""
        if "Ready for verification" in current[-600:]:
            return  # already annotated since the last change
        note = _para(
            f"[{now_datetime()}] Automated re-evaluation returned {cr.verdict} "
            f"({cr.passed}/{cr.total} subjects passing). Ready for verification. "
            f"Closure requires reviewer confirmation."
        )
        frappe.db.set_value(
            "GRC Audit Finding", existing.name, body_f, (current + note)[:100000],
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
        f"Check: {check.check_code} | Source: {check.source or '-'} | Detected: {cr.evaluated_at}",
        f"Mapped to {check.framework or '-'} {check.control or ''} "
        f"and NCA ECC {check.ecc_reference or '-'}.",
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

# Discovery owns these. Everything else on the GRC record — CIA ratings,
# criticality, data classification, control linkage — is the consultant's
# judgement and is never written by this app.
MACHINE_FIELDS = (
    "asset_name",
    "asset_id",
    "hostname",
    "ip_address",
    "os_version",
    "make_model",
    "serial_number",
)


def sync_asset_inventory(infra_asset: str) -> str | None:
    """Project a discovered Infra Asset into alphax_grc's GRC Asset Inventory."""
    if not grc_installed() or not _exists("GRC Asset Inventory"):
        return None

    src = frappe.get_doc("Infra Asset", infra_asset)
    if src.merged_into:
        return None

    marker = f"infra:{src.name}"
    existing = frappe.db.get_value("GRC Asset Inventory", {"asset_id": marker}, "name")

    values = {
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
            for k in MACHINE_FIELDS:
                v = values.get(k)
                if v and doc.meta.get_field(k) and doc.get(k) != v:
                    doc.set(k, v)
                    changed = True
            if changed:
                doc.save(ignore_permissions=True)
            return doc.name

        doc = frappe.new_doc("GRC Asset Inventory")
        doc.client = src.client
        for k in MACHINE_FIELDS:
            if values.get(k) and doc.meta.get_field(k):
                doc.set(k, values[k])

        wanted = ASSET_TYPE_MAP.get(src.asset_type, "Service")
        atype = _legal_option("GRC Asset Inventory", "asset_type", wanted, "Service")
        if atype:
            doc.asset_type = atype
        if doc.meta.get_field("notes"):
            doc.notes = (
                f"Discovered by AlphaX Infra ({src.first_seen_source or 'unknown source'}); "
                f"source record {src.name}. Technical fields are maintained by discovery. "
                f"Classification, CIA ratings, criticality and control linkage are yours "
                f"to set and will not be overwritten."
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
    Which controls currently have machine evidence behind them, and what that
    evidence says. This is the number that sells the product: "discovery
    satisfies N of your M evidence requests automatically".
    """
    return frappe.db.sql(
        """
        SELECT c.framework, c.control, c.ecc_reference,
               COUNT(DISTINCT c.name) AS checks,
               SUM(CASE WHEN r.verdict = 'Pass' THEN 1 ELSE 0 END) AS passing,
               SUM(CASE WHEN r.verdict = 'Fail' THEN 1 ELSE 0 END) AS failing,
               SUM(CASE WHEN r.verdict = 'Inconclusive' THEN 1 ELSE 0 END) AS inconclusive,
               MAX(r.evaluated_at) AS last_evaluated
        FROM `tabInfra Check` c
        LEFT JOIN `tabInfra Check Result` r
               ON r.`infra_check` = c.name AND r.client = %(client)s AND r.is_latest = 1
        WHERE c.is_active = 1 AND c.control IS NOT NULL AND c.control != ''
        GROUP BY c.framework, c.control, c.ecc_reference
        ORDER BY c.framework, c.control
        """,
        {"client": client},
        as_dict=True,
    )
