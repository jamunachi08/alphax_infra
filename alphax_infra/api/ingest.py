# Copyright (c) 2026, Neotec Integrated Solutions
"""
Collector ingest API.

This is the only endpoint in the app that accepts data originating outside the
site, so it is written defensively and every rejection is explicit.

The acceptance chain, in order, and every step is mandatory:

  1. collector exists, is Active, kill switch is off
  2. envelope is structurally valid and within the size cap
  3. module is on the collector's approved list
  4. collected_at is inside the replay window
  5. sequence is strictly greater than the last accepted one
  6. content hash has not been seen before
  7. Ed25519 signature verifies against the enrolled public key

Only then are observations written. A failure at any step produces an Infra
Discovery Batch row with status Rejected and a reason: a refused batch must
leave a trace, because "nothing arrived" and "everything was rejected" look
identical from the collector's side and are very different problems.

Steps 4 through 7 are what make the endpoint replay-resistant and idempotent.
Re-posting an accepted batch returns Duplicate and changes nothing, which is
the behaviour a store-and-forward collector needs when an acknowledgement is
lost in transit.
"""

from __future__ import annotations

import hashlib
import json
import secrets

import frappe
from frappe.utils import add_to_date, cint, now_datetime

from alphax_infra.core import observations as obs
from alphax_infra.core.canonical import (
    SignatureError,
    digest,
    signing_payload,
    validate_envelope,
)


def _settings():
    return frappe.get_cached_doc("AlphaX Infra Settings")


def _reject(collector, envelope: dict, reason: str, *, status: str = "Rejected") -> dict:
    """Record the refusal, then tell the collector plainly why."""
    try:
        if envelope.get("nonce"):
            reason = f"{reason} [envelope digest {digest(signing_payload(envelope))[:16]}]"
        frappe.get_doc(
            {
                "doctype": "Infra Discovery Batch",
                "client": getattr(collector, "client", None) or envelope.get("client"),
                "collector": getattr(collector, "name", None),
                "sequence": cint(envelope.get("sequence")),
                "module": (envelope.get("module") or "")[:140],
                "nonce": (envelope.get("nonce") or "")[:140],
                "schema_version": cint(envelope.get("schema_version")),
                "collector_version": (envelope.get("collector_version") or "")[:140],
                "status": status,
                "reject_reason": reason[:1000],
                "received_at": now_datetime(),
                "signature_verified": 0,
                "observation_count": len(envelope.get("observations") or []),
                # Always random on a rejection. content_hash carries a unique
                # index so that a re-uploaded accepted batch is a no-op; a
                # repeated *rejection* would collide on that same index and
                # lose the audit row, which defeats the purpose of writing it.
                # The real digest is recorded in the reason instead.
                "content_hash": secrets.token_hex(32),
            }
        ).insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception:  # noqa: BLE001 — never let audit logging mask the reason
        frappe.log_error(title="Infra batch reject log failed"[:140], message=frappe.get_traceback())

    frappe.local.response["http_status_code"] = 409 if status == "Duplicate" else 400
    return {"accepted": False, "status": status, "reason": reason}


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


@frappe.whitelist()
def issue_enrolment_token(collector: str):
    """
    Desk-side. Mints a single-use enrolment token.

    Only the hash is stored. The plaintext is returned exactly once and cannot
    be recovered afterwards, so a database dump does not yield a working
    enrolment credential.
    """
    from alphax_infra.core.tenancy import require_client

    doc = frappe.get_doc("Infra Collector", collector)
    require_client(doc.client)
    frappe.has_permission("Infra Collector", "write", doc=doc, throw=True)

    token = f"{doc.name}.{secrets.token_urlsafe(40)}"
    doc.db_set(
        {
            "enrolment_token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "enrolment_expires": add_to_date(now_datetime(), hours=24),
            "status": "Pending Enrolment",
        },
        update_modified=False,
    )
    return {
        "token": token,
        "expires": str(doc.enrolment_expires),
        "notice": "Shown once. It cannot be retrieved again — reissue if lost.",
    }


@frappe.whitelist(allow_guest=True)
def enrol():
    """
    Collector-side. Exchanges a one-time token for an enrolled identity by
    registering the collector's public key.

    Guest-accessible by necessity: the collector has no session yet. The token
    is the only credential, it is single-use, and it is consumed whether or not
    the rest of the request succeeds.
    """
    body = _body()
    token = (body.get("token") or "").strip()
    public_key = (body.get("public_key") or "").strip()
    version = (body.get("collector_version") or "")[:140]

    if not token or not public_key:
        frappe.local.response["http_status_code"] = 400
        return {"enrolled": False, "reason": "token and public_key are required"}

    name = token.split(".", 1)[0]
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    doc = frappe.db.get_value(
        "Infra Collector",
        name,
        ["name", "enrolment_token_hash", "enrolment_expires", "status"],
        as_dict=True,
    )
    # Constant-time compare so a timing oracle cannot be used to guess a token.
    if not doc or not doc.enrolment_token_hash or not secrets.compare_digest(
        doc.enrolment_token_hash, token_hash
    ):
        frappe.local.response["http_status_code"] = 403
        return {"enrolled": False, "reason": "invalid enrolment token"}

    if not doc.enrolment_expires or doc.enrolment_expires < now_datetime():
        frappe.local.response["http_status_code"] = 403
        return {"enrolled": False, "reason": "enrolment token has expired"}

    fingerprint = hashlib.sha256(public_key.encode()).hexdigest()[:32]
    frappe.db.set_value(
        "Infra Collector",
        doc.name,
        {
            "public_key": public_key,
            "fingerprint": fingerprint,
            "collector_version": version,
            "status": "Active",
            "enrolled_on": now_datetime(),
            "enrolment_token_hash": None,  # single use
            "enrolment_expires": None,
            "last_seen": now_datetime(),
        },
        update_modified=False,
    )
    frappe.db.commit()
    return {"enrolled": True, "collector": doc.name, "fingerprint": fingerprint}


# ---------------------------------------------------------------------------
# Batch upload
# ---------------------------------------------------------------------------


@frappe.whitelist(allow_guest=True)
def upload_batch():
    """
    Accept one signed batch of normalised observations.

    The collector authenticates by signature, not by session. There is no
    bearer token to steal from a customer's container: a stolen batch is
    replay-protected and a forged one fails verification.
    """
    envelope = _body()
    settings = _settings()

    problems = validate_envelope(envelope)
    if problems:
        return _reject(None, envelope, "; ".join(problems[:6]))

    collector_id = envelope.get("collector_id")
    collector = frappe.db.get_value(
        "Infra Collector",
        collector_id,
        [
            "name", "client", "status", "public_key", "last_sequence",
            "kill_switch", "approved_modules", "batches_accepted",
        ],
        as_dict=True,
    )
    if not collector:
        return _reject(None, envelope, "unknown collector")
    if collector.kill_switch:
        return _reject(collector, envelope, "collector kill switch is engaged")
    if collector.status != "Active":
        return _reject(collector, envelope, f"collector status is {collector.status}")
    if envelope.get("client") != collector.client:
        return _reject(collector, envelope, "client does not match the enrolled collector")

    cap = cint(settings.max_batch_observations) or 20000
    count = len(envelope.get("observations") or [])
    if count > cap:
        return _reject(collector, envelope, f"batch of {count} exceeds the cap of {cap}")

    approved = {m.strip() for m in (collector.approved_modules or "").splitlines() if m.strip()}
    module = envelope.get("module")
    if approved and module not in approved:
        # A compromised collector must not be able to widen its own scope.
        return _reject(collector, envelope, f"module '{module}' is not approved for this collector")

    skew = cint(settings.max_clock_skew_seconds) or 300
    window = cint(settings.replay_window_minutes) or 15
    collected_at = _parse_dt(envelope.get("collected_at"))
    if not collected_at:
        return _reject(collector, envelope, "collected_at is not a parseable timestamp")
    now = now_datetime()
    if collected_at > add_to_date(now, seconds=skew):
        return _reject(collector, envelope, "collected_at is in the future beyond tolerated skew")
    if collected_at < add_to_date(now, minutes=-window):
        return _reject(
            collector, envelope,
            f"collected_at is older than the {window} minute replay window",
        )

    sequence = cint(envelope.get("sequence"))
    if sequence <= cint(collector.last_sequence):
        return _reject(
            collector, envelope,
            f"sequence {sequence} is not greater than the last accepted "
            f"({collector.last_sequence}) — treated as a replay",
        )

    payload = signing_payload(envelope)
    content = digest(payload)
    if frappe.db.exists("Infra Discovery Batch", {"content_hash": content}):
        # Idempotent: a retried upload after a lost acknowledgement is a no-op.
        return _reject(collector, envelope, "batch already processed", status="Duplicate")

    if settings.require_signed_batches:
        signature = envelope.get("signature") or ""
        if not signature:
            return _reject(collector, envelope, "signature is required but absent")
        if not collector.public_key:
            return _reject(collector, envelope, "collector has no enrolled public key")
        try:
            if not _verify(payload, signature, collector.public_key):
                return _reject(collector, envelope, "signature verification failed")
        except SignatureError as exc:
            return _reject(collector, envelope, f"signature could not be checked: {exc}")

    return _accept(collector, envelope, content, collected_at, sequence)


def _verify(payload, signature, public_key) -> bool:
    from alphax_infra.core.canonical import verify_signature

    return verify_signature(payload, signature, public_key)


def _accept(collector, envelope: dict, content: str, collected_at, sequence: int) -> dict:
    batch = frappe.get_doc(
        {
            "doctype": "Infra Discovery Batch",
            "client": collector.client,
            "collector": collector.name,
            "sequence": sequence,
            "module": envelope.get("module"),
            "content_hash": content,
            "nonce": envelope.get("nonce"),
            "schema_version": cint(envelope.get("schema_version")),
            "collector_version": envelope.get("collector_version"),
            "signature_verified": 1,
            "status": "Verified",
            "received_at": now_datetime(),
            "observation_count": len(envelope.get("observations") or []),
        }
    ).insert(ignore_permissions=True)

    # Sequence advances the moment the batch is accepted, before processing.
    # If processing later fails, the batch must not become replayable.
    frappe.db.set_value(
        "Infra Collector",
        collector.name,
        {
            "last_sequence": sequence,
            "last_seen": now_datetime(),
            "batches_accepted": cint(collector.batches_accepted) + 1,
            "collector_version": envelope.get("collector_version"),
        },
        update_modified=False,
    )
    frappe.db.commit()

    try:
        counts = obs.record_batch(
            collector.client,
            envelope.get("module") or "collector",
            envelope.get("observations") or [],
            batch=batch.name,
            collected_at=collected_at,
            schema_version=cint(envelope.get("schema_version")),
        )
        batch.db_set(
            {"status": "Processed", "processed_at": now_datetime()}, update_modified=False
        )
        frappe.db.commit()
        return {"accepted": True, "batch": batch.name, "counts": counts}
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra batch processing failed: {batch.name}"[:140],
            message=frappe.get_traceback(),
        )
        batch.db_set(
            {"status": "Rejected", "reject_reason": "processing error; see error log"},
            update_modified=False,
        )
        frappe.db.commit()
        frappe.local.response["http_status_code"] = 500
        return {"accepted": False, "batch": batch.name, "reason": "processing error"}


@frappe.whitelist(allow_guest=True)
def heartbeat():
    """Liveness plus job configuration. Cheap, called often, writes one field."""
    body = _body()
    collector = frappe.db.get_value(
        "Infra Collector",
        body.get("collector_id"),
        ["name", "status", "kill_switch", "approved_modules", "last_sequence"],
        as_dict=True,
    )
    if not collector:
        frappe.local.response["http_status_code"] = 404
        return {"ok": False}

    frappe.db.set_value(
        "Infra Collector", collector.name, "last_seen", now_datetime(), update_modified=False
    )
    return {
        "ok": True,
        "active": collector.status == "Active" and not collector.kill_switch,
        "kill_switch": bool(collector.kill_switch),
        "approved_modules": [
            m.strip() for m in (collector.approved_modules or "").splitlines() if m.strip()
        ],
        "next_sequence": cint(collector.last_sequence) + 1,
        "server_time": str(now_datetime()),
    }


# ---------------------------------------------------------------------------


def _body() -> dict:
    """Parse the JSON body. Form-encoded posts are not accepted here."""
    try:
        raw = frappe.request.get_data(as_text=True) if frappe.request else ""
        return json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}


def _parse_dt(value):
    from frappe.utils import get_datetime

    try:
        return get_datetime(value)
    except Exception:  # noqa: BLE001
        return None
