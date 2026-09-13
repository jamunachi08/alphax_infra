# Copyright (c) 2026, Neotec Integrated Solutions
"""
Check evaluation and GRC write-back.

Separated from discovery on purpose. Collection and assessment are different
activities with different failure modes: a connector outage should not stop
checks running against yesterday's facts, and a bad check definition should not
lose a discovery run. They meet only through the observation store.

Every evaluation writes an Infra Check Result and demotes the previous one.
Results are never overwritten, because a compliance product whose history can
be silently rewritten is not evidence, it is a dashboard.
"""

from __future__ import annotations

import json

import frappe
from frappe.utils import cint, now_datetime

from alphax_infra.core import grc_bridge
from alphax_infra.core.rules import CheckDefinitionError, FAIL, run_check
from alphax_infra.core.tenancy import allowed_clients


def evaluate_check(check_name: str, client: str, *, as_of=None) -> dict:
    """Run one check for one client and persist the result."""
    check = frappe.get_doc("Infra Check", check_name)

    if check.client and check.client != client:
        return {"skipped": "check is scoped to a different client"}

    try:
        result = run_check(check.parsed_definition(), client, as_of=as_of)
        payload = result.as_dict()
    except CheckDefinitionError as exc:
        # A malformed definition is a content defect, not a control failure.
        # Recording it as Inconclusive keeps it visible without producing a
        # false finding against the customer.
        payload = {
            "verdict": "Inconclusive",
            "total": 0,
            "passed": 0,
            "failed": 0,
            "pass_rate": 0,
            "failing_subjects": [],
            "detail": {"error": str(exc), "reason": "check definition is invalid"},
        }

    row = _persist(check, client, payload, as_of)

    if check.write_evidence:
        evidence = grc_bridge.upsert_evidence(row.name)
        if evidence:
            row.db_set("grc_evidence", evidence, update_modified=False)

    finding = grc_bridge.upsert_finding(row.name)
    if finding:
        row.db_set("grc_finding", finding, update_modified=False)

    check.db_set(
        {
            "last_evaluated": now_datetime(),
            "last_verdict": payload["verdict"],
            "last_pass_rate": payload["pass_rate"],
        },
        update_modified=False,
    )

    return {"result": row.name, **payload}


def _persist(check, client: str, payload: dict, as_of):
    # Demote prior results first so there is never a window with two latest
    # rows for the same check.
    frappe.db.sql(
        """
        UPDATE `tabInfra Check Result`
        SET `is_latest` = 0
        WHERE `check` = %(check)s AND `client` = %(client)s AND `is_latest` = 1
        """,
        {"check": check.name, "client": client},
    )

    row = frappe.new_doc("Infra Check Result")
    row.update(
        {
            "client": client,
            "check": check.name,
            "verdict": payload["verdict"],
            "total": payload["total"],
            "passed": payload["passed"],
            "failed": payload["failed"],
            "pass_rate": payload["pass_rate"],
            "evaluated_at": now_datetime(),
            "as_of": as_of,
            "is_latest": 1,
            "failing_subjects": json.dumps(payload.get("failing_subjects") or []),
            "detail": json.dumps(payload.get("detail") or {}, default=str),
        }
    )
    row.insert(ignore_permissions=True)
    return row


def evaluate_all(client: str, *, source: str | None = None, as_of=None) -> dict:
    """Run every active check for one client."""
    filters = {"is_active": 1}
    if source:
        filters["source"] = source

    names = frappe.get_all("Infra Check", filters=filters, pluck="name", order_by="check_code")
    summary = {"Pass": 0, "Fail": 0, "Inconclusive": 0, "Not Applicable": 0, "errors": 0}

    for name in names:
        scoped = frappe.db.get_value("Infra Check", name, "client")
        if scoped and scoped != client:
            continue
        try:
            out = evaluate_check(name, client, as_of=as_of)
            if "verdict" in out:
                summary[out["verdict"]] = summary.get(out["verdict"], 0) + 1
        except Exception:  # noqa: BLE001 — one bad check never stops the batch
            summary["errors"] += 1
            frappe.log_error(
                title=f"Infra check evaluation failed: {name}"[:140],
                message=frappe.get_traceback(),
            )
        frappe.db.commit()

    return summary


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"Critical": 5, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def readiness(client: str) -> dict:
    """
    Severity-weighted readiness with coverage stated alongside it.

    Two rules from the specification are enforced here rather than described.
    Inconclusive checks never count as passes — they are reported separately,
    so a customer with no connectors configured scores 0% coverage rather than
    100% compliance. And a failing Critical check sets a hard gate flag, because
    an average that hides an open management port on the internet is worse than
    no number at all.
    """
    rows = frappe.db.sql(
        """
        SELECT c.severity, r.verdict, COUNT(*) AS n
        FROM `tabInfra Check Result` r
        INNER JOIN `tabInfra Check` c ON c.name = r.check
        WHERE r.client = %(client)s AND r.is_latest = 1 AND c.is_active = 1
        GROUP BY c.severity, r.verdict
        """,
        {"client": client},
        as_dict=True,
    )

    weighted_total = weighted_pass = 0
    counts = {"Pass": 0, "Fail": 0, "Inconclusive": 0, "Not Applicable": 0}
    hard_gate_failures = 0

    for r in rows:
        n = cint(r.n)
        counts[r.verdict] = counts.get(r.verdict, 0) + n
        if r.verdict == "Not Applicable":
            continue  # excluded from the denominator, as the spec requires
        if r.verdict == "Inconclusive":
            continue  # reported as coverage, never as a score
        w = SEVERITY_WEIGHT.get(r.severity, 1) * n
        weighted_total += w
        if r.verdict == "Pass":
            weighted_pass += w
        elif r.severity == "Critical":
            hard_gate_failures += n

    assessed = counts["Pass"] + counts["Fail"]
    total_evaluated = assessed + counts["Inconclusive"]

    return {
        "readiness_percent": round(100.0 * weighted_pass / weighted_total, 1) if weighted_total else 0.0,
        "hard_gate_failures": hard_gate_failures,
        "hard_gate_clear": hard_gate_failures == 0,
        "checks_passing": counts["Pass"],
        "checks_failing": counts["Fail"],
        "checks_inconclusive": counts["Inconclusive"],
        "checks_not_applicable": counts["Not Applicable"],
        "coverage_percent": round(100.0 * assessed / total_evaluated, 1) if total_evaluated else 0.0,
        "basis": "Severity-weighted over assessed checks. Inconclusive results are excluded "
                 "from the score and reported as reduced coverage. This is a readiness "
                 "indicator, not a statement of certification.",
    }


# ---------------------------------------------------------------------------
# Whitelisted entry points
# ---------------------------------------------------------------------------


@frappe.whitelist()
def run_all(client: str, source: str | None = None):
    from alphax_infra.core.tenancy import require_client

    client = require_client(client)
    frappe.enqueue(
        "alphax_infra.evaluate.evaluate_all",
        queue="long",
        timeout=1800,
        client=client,
        source=source,
    )
    return {"ok": True, "message": "Evaluation queued."}


@frappe.whitelist()
def get_readiness(client: str | None = None):
    from alphax_infra.core.tenancy import require_client

    return readiness(require_client(client))


@frappe.whitelist()
def get_control_coverage(client: str | None = None):
    from alphax_infra.core.tenancy import require_client

    return grc_bridge.control_coverage(require_client(client))


@frappe.whitelist()
def my_clients():
    """Used by the cockpit to populate its client selector."""
    allowed = allowed_clients()
    if allowed == ["*"]:
        return frappe.get_all("GRC Client Profile", fields=["name", "client_name"], limit=200)
    return frappe.get_all(
        "GRC Client Profile", filters={"name": ["in", allowed]}, fields=["name", "client_name"]
    )
