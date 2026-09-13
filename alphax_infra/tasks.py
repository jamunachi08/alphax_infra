# Copyright (c) 2026, Neotec Integrated Solutions
"""
Scheduled work.

Every task here follows the same shape: iterate, isolate failures per item,
never raise out of the scheduler. A background job that throws takes the whole
scheduled batch with it, and on a consulting site that means one broken
client's connector silently stops discovery for every other client.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import add_days, add_to_date, cint, now_datetime


def _settings():
    return frappe.get_cached_doc("AlphaX Infra Settings")


def _enabled() -> bool:
    try:
        return bool(_settings().enabled)
    except Exception:  # noqa: BLE001 — before first install of the Single doc
        return False


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def run_scheduled_connectors():
    if not _enabled():
        return

    from alphax_infra.discovery import run_connector_job

    today_is_monday = now_datetime().weekday() == 0
    connectors = frappe.get_all(
        "Infra Connector",
        filters={"enabled": 1, "status": "Active"},
        fields=["name", "schedule"],
    )

    for c in connectors:
        if c.schedule == "Manual":
            continue
        if c.schedule == "Weekly" and not today_is_monday:
            continue
        try:
            run_connector_job(c.name, triggered_by="scheduler")
        except Exception:  # noqa: BLE001
            frappe.log_error(
                title=f"Infra scheduled connector failed: {c.name}"[:140],
                message=frappe.get_traceback(),
            )
        frappe.db.commit()


def evaluate_daily_checks():
    """
    Re-evaluate checks for every client that has observation data.

    Deliberately runs after the connector pass in the same scheduler slot, so
    the day's checks see the day's facts. If a connector failed, checks still
    run against the last known good observations and the ageing shows up as
    reduced evidence freshness rather than as a missing result.
    """
    if not _enabled():
        return

    from alphax_infra.core import observations as obs
    from alphax_infra.evaluate import evaluate_all

    if not obs.table_exists():
        return

    clients = frappe.db.sql(
        f"SELECT DISTINCT `client` FROM `{obs.TABLE}` WHERE `valid_to` IS NULL", pluck=True
    )
    for client in clients:
        try:
            evaluate_all(client)
        except Exception:  # noqa: BLE001
            frappe.log_error(
                title=f"Infra daily evaluation failed: {client}"[:140],
                message=frappe.get_traceback(),
            )
        frappe.db.commit()


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def expire_consent_records():
    """
    Consent that has passed its end date stops authorising collection today,
    not at the next manual review. The connector controller refuses to run
    without active consent, so this is what actually halts data flow.
    """
    now = now_datetime()
    stale = frappe.get_all(
        "Infra Consent Record",
        filters={"status": "Active", "valid_until": ["<", now]},
        pluck="name",
    )
    for name in stale:
        try:
            doc = frappe.get_doc("Infra Consent Record", name)
            doc.status = "Expired"
            doc.save(ignore_permissions=True)  # on_update disables the connectors
        except Exception:  # noqa: BLE001
            frappe.log_error(
                title=f"Infra consent expiry failed: {name}"[:140], message=frappe.get_traceback()
            )
        frappe.db.commit()


def expire_assessment_sessions():
    now = now_datetime()
    sessions = frappe.get_all(
        "Infra Assessment Session",
        filters={
            "status": ["in", ["Invited", "Draft", "Consented"]],
            "expires_on": ["<", now],
        },
        pluck="name",
    )
    for name in sessions:
        # The token hash is cleared as well as the status: an expired
        # invitation link must stop working, not merely look expired.
        frappe.db.set_value(
            "Infra Assessment Session",
            name,
            {"status": "Expired", "invitation_token_hash": None},
            update_modified=False,
        )
    frappe.db.commit()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def alert_stale_collectors():
    """
    A collector that stopped reporting is indistinguishable from a clean
    estate unless somebody is told. Silence is the failure mode this exists
    to prevent.
    """
    cutoff = add_to_date(now_datetime(), hours=-48)
    stale = frappe.get_all(
        "Infra Collector",
        filters={"status": "Active", "kill_switch": 0, "last_seen": ["<", cutoff]},
        fields=["name", "collector_label", "client", "last_seen"],
    )
    if not stale:
        return

    lines = [
        f"• {c.collector_label} ({c.client}) — last seen {c.last_seen}" for c in stale
    ]
    _notify(
        subject=_("AlphaX Infra: {0} collector(s) have stopped reporting").format(len(stale)),
        message=(
            "These collectors have not checked in for over 48 hours. Until they "
            "resume, any check depending on their data is running against ageing "
            "observations.\n\n" + "\n".join(lines)
        ),
    )


def alert_critical_failures():
    """New Critical-severity failures since yesterday."""
    since = add_days(now_datetime(), -1)
    rows = frappe.db.sql(
        """
        SELECT r.client, c.check_code, c.check_name, r.failed, r.total
        FROM `tabInfra Check Result` r
        INNER JOIN `tabInfra Check` c ON c.name = r.`infra_check`
        WHERE r.is_latest = 1
          AND r.verdict = 'Fail'
          AND c.severity = 'Critical'
          AND r.evaluated_at >= %(since)s
        ORDER BY r.client, c.check_code
        """,
        {"since": since},
        as_dict=True,
    )
    if not rows:
        return

    lines = [
        f"• [{r.client}] {r.check_code} {r.check_name} — {r.failed} of {r.total} failing"
        for r in rows
    ]
    _notify(
        subject=_("AlphaX Infra: {0} critical check failure(s)").format(len(rows)),
        message=(
            "These are hard-gate failures. An assessment cannot be signed off as "
            "ready while any of them stands.\n\n" + "\n".join(lines)
        ),
    )


def _notify(subject: str, message: str) -> None:
    recipients = frappe.get_all(
        "Has Role",
        filters={"role": "Infra Admin", "parenttype": "User"},
        pluck="parent",
    )
    recipients = [
        r for r in set(recipients)
        if frappe.db.get_value("User", r, "enabled") and "@" in r
    ]
    if not recipients:
        return
    try:
        frappe.sendmail(recipients=recipients, subject=subject, message=message.replace("\n", "<br>"))
    except Exception:  # noqa: BLE001 — mail failure must not break the scheduler
        frappe.log_error(title="Infra alert email failed"[:140], message=frappe.get_traceback())


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def purge_expired_observations():
    """
    Delete superseded observations past the retention window.

    Off by default. Purging history is irreversible and shortens the window in
    which a point-in-time question can be answered, so it is a deliberate
    per-site decision rather than a default behaviour.
    """
    if not _enabled():
        return
    settings = _settings()
    if not settings.purge_enabled:
        return

    from alphax_infra.core import observations as obs

    if not obs.table_exists():
        return

    days = cint(settings.historical_observation_days) or 400
    before = add_days(now_datetime(), -days)

    clients = frappe.db.sql(
        f"SELECT DISTINCT `client` FROM `{obs.TABLE}`", pluck=True
    )
    for client in clients:
        try:
            obs.purge_raw(client, before)
        except Exception:  # noqa: BLE001
            frappe.log_error(
                title=f"Infra purge failed: {client}"[:140], message=frappe.get_traceback()
            )
        frappe.db.commit()


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def guard_asset_deletion(doc, method=None):
    """
    Refuse to delete an asset that observations or findings point at.

    Deleting it would orphan the evidence chain that a report conclusion rests
    on. Decommissioned is a lifecycle state, not a deletion.
    """
    from alphax_infra.core import observations as obs

    if not obs.table_exists():
        return

    count = frappe.db.sql(
        f"SELECT COUNT(*) FROM `{obs.TABLE}` WHERE `asset` = %(name)s",
        {"name": doc.name},
    )[0][0]
    if count:
        frappe.throw(
            _(
                "This asset has {0} observations attached. Deleting it would break the "
                "evidence chain for any conclusion that cites it. Set its lifecycle to "
                "Decommissioned instead."
            ).format(count)
        )
