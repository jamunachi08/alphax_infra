# Copyright (c) 2026, Neotec Integrated Solutions
"""
Discovery orchestration.

One function matters here: `run_connector_job`. It authorises, fetches,
persists and correlates, and it writes a job record whatever happens. The job
row is the audit trail, so it is created before any network call and closed in
a finally block — a discovery run that crashed must leave evidence that it
crashed, not silence.

Order of operations is deliberate. Observations are written before assets are
correlated, because observations are the record of fact and correlation is an
interpretation of them. If correlation fails we still hold the facts and can
re-correlate; if it were the other way round a correlation bug would lose data.
"""

from __future__ import annotations

import json

import frappe
from frappe.utils import cint, now_datetime

from alphax_infra.connectors import base as connectors
from alphax_infra.core import correlation
from alphax_infra.core import observations as obs
from alphax_infra.core.tenancy import require_client


def settings():
    return frappe.get_cached_doc("AlphaX Infra Settings")


# ---------------------------------------------------------------------------
# Connector runs
# ---------------------------------------------------------------------------


def run_connector_job(connector_name: str, *, triggered_by: str = "manual") -> str:
    """Run one connector end to end. Returns the job name."""
    conn = frappe.get_doc("Infra Connector", connector_name)

    job = frappe.new_doc("Infra Discovery Job")
    job.update(
        {
            "client": conn.client,
            "job_type": "Connector",
            "connector": conn.name,
            "module": conn.connector_type,
            "state": "Running",
            "started_at": now_datetime(),
        }
    )
    job.insert(ignore_permissions=True)
    frappe.db.commit()  # the job row must survive a later crash

    metrics: dict = {"triggered_by": triggered_by}
    try:
        _authorise(conn)
        job.db_set("state", "Running", update_modified=False)

        result = connectors.run(conn.connector_type, conn.name)
        metrics.update(
            {"api_calls": result.api_calls, "pages": result.pages, "notes": result.notes}
        )

        if not result.ok:
            _close(job, "Failed", metrics, error=result.error)
            _record_connector_health(conn, "Failed", result.error)
            return job.name

        cap = cint(settings().max_batch_observations) or 20000
        if len(result.observations) > cap:
            metrics["observations_truncated"] = len(result.observations) - cap
            result.observations = result.observations[:cap]

        counts = obs.record_batch(
            conn.client,
            conn.connector_type,
            result.observations,
            batch=job.name,
            collected_at=job.started_at,
        )
        metrics["observations"] = counts

        touched = _upsert_assets(conn.client, conn.connector_type, result.assets)
        metrics["assets"] = touched

        job.db_set(
            {
                "observations_received": len(result.observations),
                "observations_new": counts["inserted"],
                "observations_unchanged": counts["unchanged"],
                "assets_touched": touched.get("created", 0) + touched.get("updated", 0),
            },
            update_modified=False,
        )

        state = "Partial" if result.notes.get("paging_truncated") else "Completed"
        _close(job, state, metrics)
        _record_connector_health(conn, "Success", None)
        return job.name

    except frappe.PermissionError as exc:
        _close(job, "Cancelled", metrics, error=str(exc))
        raise
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra discovery job failed: {job.name}"[:140],
            message=frappe.get_traceback(),
        )
        _close(job, "Failed", metrics, error="unhandled error; see error log")
        _record_connector_health(conn, "Failed", "unhandled error")
        return job.name


def _authorise(conn) -> None:
    """Consent, enablement and kill-switch checks, in that order."""
    if not settings().enabled:
        raise frappe.PermissionError("AlphaX Infra is disabled in settings.")
    if not conn.enabled:
        raise frappe.PermissionError(f"Connector {conn.name} is not enabled.")
    if not conn.consent_reference:
        raise frappe.PermissionError(f"Connector {conn.name} has no consent record.")

    consent = frappe.get_doc("Infra Consent Record", conn.consent_reference)
    if consent.status != "Active":
        raise frappe.PermissionError(f"Consent {consent.name} is {consent.status}.")
    if consent.valid_until and consent.valid_until < now_datetime():
        consent.db_set("status", "Expired", update_modified=False)
        raise frappe.PermissionError(f"Consent {consent.name} expired on {consent.valid_until}.")


def _close(job, state: str, metrics: dict, error: str | None = None) -> None:
    job.db_set(
        {
            "state": state,
            "finished_at": now_datetime(),
            "metrics": json.dumps(metrics, default=str)[:100000],
            "error_summary": (error or "")[:1000],
        },
        update_modified=False,
    )
    frappe.db.commit()


def _record_connector_health(conn, result: str, error: str | None) -> None:
    failures = 0 if result == "Success" else cint(conn.consecutive_failures) + 1
    updates = {
        "last_run": now_datetime(),
        "last_result": result,
        "last_error": (error or "")[:500],
        "consecutive_failures": failures,
    }
    # Three failures in a row is a broken integration, not a blip. Flipping
    # status stops the nightly scheduler from hammering a revoked app
    # registration and getting the tenant rate-limited.
    if failures >= 3:
        updates["status"] = "Error"
        updates["enabled"] = 0
    conn.db_set(updates, update_modified=False)


# ---------------------------------------------------------------------------
# Asset correlation
# ---------------------------------------------------------------------------


def _upsert_assets(client: str, source: str, incoming: list) -> dict:
    created = updated = proposed = 0
    auto_merge = bool(settings().auto_merge_enabled)

    for item in incoming:
        identifiers = [
            i for i in (item.get("identifiers") or [])
            if correlation.normalise(i.get("identifier_type"), i.get("identifier_value"))
        ]
        if not identifiers:
            # An asset with no usable identifier cannot be deduplicated and
            # would pollute the estate on every run. Skip it rather than
            # create a record that can never be matched again.
            continue

        verdict = correlation.correlate(client, {**item, "identifiers": identifiers})

        if verdict["action"] == "auto_merge" and auto_merge and verdict["asset"]:
            _refresh_asset(verdict["asset"], source, item, identifiers)
            updated += 1
        elif verdict["action"] in ("review", "auto_merge") and verdict["asset"]:
            name = _create_asset(client, source, item, identifiers)
            _propose_merge(client, verdict["asset"], name, verdict)
            created += 1
            proposed += 1
        else:
            _create_asset(client, source, item, identifiers)
            created += 1

    return {"created": created, "updated": updated, "merge_proposals": proposed}


def _create_asset(client: str, source: str, item: dict, identifiers: list) -> str:
    doc = frappe.new_doc("Infra Asset")
    doc.update(
        {
            "client": client,
            "asset_name": (item.get("asset_name") or "unnamed")[:140],
            "asset_type": item.get("asset_type") or "Other",
            "hostname": item.get("hostname"),
            "ip_address": item.get("ip_address"),
            "os_version": item.get("os_version"),
            "make_model": item.get("make_model"),
            "serial_number": item.get("serial_number"),
            "first_seen": now_datetime(),
            "first_seen_source": source,
            "last_seen": now_datetime(),
            "last_seen_source": source,
            "source_count": 1,
        }
    )
    for i in identifiers:
        doc.append("identifiers", {**i, "source": source})
    doc.insert(ignore_permissions=True)
    return doc.name


def _refresh_asset(name: str, source: str, item: dict, identifiers: list) -> None:
    doc = frappe.get_doc("Infra Asset", name)

    known = {(i.identifier_type, i.normalised_value) for i in (doc.identifiers or [])}
    added = False
    for i in identifiers:
        norm = correlation.normalise(i["identifier_type"], i["identifier_value"])
        if (i["identifier_type"], norm) not in known:
            doc.append("identifiers", {**i, "source": source})
            added = True

    # Technical attributes are refreshed from the source; nothing a human set
    # is touched here.
    for field in ("hostname", "ip_address", "os_version", "make_model", "serial_number"):
        if item.get(field):
            doc.set(field, item[field])

    doc.last_seen = now_datetime()
    doc.last_seen_source = source
    if source != doc.first_seen_source and added:
        doc.source_count = cint(doc.source_count) + 1
    doc.save(ignore_permissions=True)


def _propose_merge(client: str, primary: str, duplicate: str, verdict: dict) -> None:
    if frappe.db.exists(
        "Infra Merge Proposal",
        {"primary_asset": primary, "duplicate_asset": duplicate, "status": "Pending"},
    ):
        return
    frappe.get_doc(
        {
            "doctype": "Infra Merge Proposal",
            "client": client,
            "primary_asset": primary,
            "duplicate_asset": duplicate,
            "match_score": verdict.get("score"),
            "matched_identifiers": "\n".join(verdict.get("matched") or []),
            "tiers": ", ".join(verdict.get("tiers") or []),
            "status": "Pending",
        }
    ).insert(ignore_permissions=True)


# ---------------------------------------------------------------------------
# Merge execution
# ---------------------------------------------------------------------------


@frappe.whitelist()
def accept_merge(proposal: str):
    """
    Apply a merge proposal.

    The duplicate is never deleted: it is marked merged_into the primary and
    its identifiers are folded in. Keeping the source record is what makes a
    wrong merge recoverable, and an unrecoverable merge is worse than a
    duplicate.
    """
    doc = frappe.get_doc("Infra Merge Proposal", proposal)
    require_client(doc.client)
    frappe.has_permission("Infra Merge Proposal", "write", doc=doc, throw=True)

    if doc.status != "Pending":
        frappe.throw(f"This proposal is already {doc.status}.")

    primary = frappe.get_doc("Infra Asset", doc.primary_asset)
    duplicate = frappe.get_doc("Infra Asset", doc.duplicate_asset)

    known = {(i.identifier_type, i.normalised_value) for i in (primary.identifiers or [])}
    for i in duplicate.identifiers or []:
        if (i.identifier_type, i.normalised_value) not in known:
            primary.append(
                "identifiers",
                {
                    "identifier_type": i.identifier_type,
                    "identifier_value": i.identifier_value,
                    "source": i.source,
                },
            )
    primary.source_count = cint(primary.source_count) + 1
    primary.save(ignore_permissions=True)

    duplicate.db_set(
        {"merged_into": primary.name, "lifecycle_state": "Ignored"}, update_modified=False
    )
    # Observations follow the surviving asset so history is not orphaned.
    frappe.db.sql(
        f"UPDATE `{obs.TABLE}` SET `asset` = %(primary)s WHERE `asset` = %(dup)s",
        {"primary": primary.name, "dup": duplicate.name},
    )

    doc.db_set(
        {"status": "Merged", "decided_by": frappe.session.user, "decided_on": now_datetime()},
        update_modified=False,
    )
    return {"ok": True, "primary": primary.name}


@frappe.whitelist()
def reject_merge(proposal: str, rationale: str):
    doc = frappe.get_doc("Infra Merge Proposal", proposal)
    require_client(doc.client)
    frappe.has_permission("Infra Merge Proposal", "write", doc=doc, throw=True)

    if not (rationale or "").strip():
        frappe.throw(
            "A rationale is required when rejecting a merge, so a recurring "
            "false match can be traced back to a reason."
        )
    doc.db_set(
        {
            "status": "Rejected",
            "rationale": rationale,
            "decided_by": frappe.session.user,
            "decided_on": now_datetime(),
        },
        update_modified=False,
    )
    return {"ok": True}


@frappe.whitelist()
def run_now(connector: str):
    """Desk button. Enqueued so a slow tenant cannot time out the request."""
    conn = frappe.get_doc("Infra Connector", connector)
    require_client(conn.client)
    frappe.has_permission("Infra Connector", "write", doc=conn, throw=True)

    frappe.enqueue(
        "alphax_infra.discovery.run_connector_job",
        queue="long",
        timeout=3600,
        connector_name=connector,
        triggered_by=frappe.session.user,
    )
    return {"ok": True, "message": "Discovery queued. The job record will show progress."}
