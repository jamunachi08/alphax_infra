# Copyright (c) 2026, Neotec Integrated Solutions
"""
The observation store.

Deliberate design decision, documented here because it looks unusual for a
Frappe app: observations are NOT a DocType. They live in `__infra_observation`,
a plain InnoDB table that the Frappe ORM never touches.

Reasoning. A pilot tenant produces on the order of 100k observations per
discovery cycle. Writing those through `frappe.get_doc().insert()` costs a
document controller instantiation, a naming series round trip, a version row
and a modified-timestamp write per record. On a Frappe Cloud instance that
turns a two-minute ingest into an hour and fills `tabVersion` with noise that
nobody will ever read. Observations are machine facts, not user documents:
they are never edited by hand, never need workflow, and never need per-record
permissions beyond the client scope.

The table is bitemporal:

  collected_at   when the collector saw it (valid time, from the source)
  recorded_at    when we stored it (transaction time, ours)
  valid_from / valid_to   the interval during which we believe this fact held

`valid_to` NULL means "still current". Superseding a fact closes the previous
row rather than updating it, so "what was true on 30 September" is a plain
WHERE clause and an auditor can be shown the answer without trusting a frozen
PDF. Retrofitting this later would mean reconstructing history that was never
recorded, which is why it is here in v0.1.0 rather than on a roadmap.

The double-underscore prefix follows Frappe's own convention for framework
tables (`__global_search`, `__UserSettings`) and keeps `bench migrate` from
mistaking it for an orphaned DocType table.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

import frappe
from frappe.utils import now_datetime

from alphax_infra.core.canonical import content_hash

TABLE = "__infra_observation"

# Chunked so a large batch never builds a single multi-megabyte INSERT that
# trips max_allowed_packet on a shared MariaDB.
INSERT_CHUNK = 500

DDL = f"""
CREATE TABLE IF NOT EXISTS `{TABLE}` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `client`        VARCHAR(140)    NOT NULL,
    `asset`         VARCHAR(140)             DEFAULT NULL,
    `subject`       VARCHAR(255)    NOT NULL,
    `source`        VARCHAR(64)     NOT NULL,
    `source_ref`    VARCHAR(140)             DEFAULT NULL,
    `fact_key`      VARCHAR(160)    NOT NULL,
    `value_json`    LONGTEXT        NOT NULL,
    `value_text`    VARCHAR(255)             DEFAULT NULL,
    `value_num`     DECIMAL(20,6)            DEFAULT NULL,
    `content_hash`  CHAR(32)        NOT NULL,
    `confidence`    SMALLINT        NOT NULL DEFAULT 100,
    `batch`         VARCHAR(140)             DEFAULT NULL,
    `schema_version` SMALLINT       NOT NULL DEFAULT 1,
    `collected_at`  DATETIME(6)     NOT NULL,
    `recorded_at`   DATETIME(6)     NOT NULL,
    `valid_from`    DATETIME(6)     NOT NULL,
    `valid_to`      DATETIME(6)              DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `ix_current`  (`client`, `fact_key`, `valid_to`),
    KEY `ix_subject`  (`client`, `subject`, `fact_key`, `valid_to`),
    KEY `ix_asset`    (`client`, `asset`, `valid_to`),
    KEY `ix_temporal` (`client`, `valid_from`, `valid_to`),
    KEY `ix_batch`    (`batch`),
    KEY `ix_dedupe`   (`client`, `subject`, `fact_key`, `content_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""


def ensure_table() -> None:
    """Idempotent. Called from after_install and after_migrate."""
    frappe.db.sql_ddl(DDL)


def table_exists() -> bool:
    return bool(frappe.db.sql(f"SHOW TABLES LIKE '{TABLE}'"))


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _scalarise(value: Any) -> tuple[str | None, float | None]:
    """
    Pull a filterable scalar out of the value so the common checks
    ("= false", "> 90 days") can run in SQL instead of in Python over the
    whole result set. Complex values keep value_json only.
    """
    if isinstance(value, bool):
        return ("true" if value else "false", 1 if value else 0)
    if isinstance(value, (int, float)):
        return (str(value), float(value))
    if isinstance(value, str):
        return (value[:255], None)
    return (None, None)


def record_batch(
    client: str,
    source: str,
    observations: Iterable[dict],
    *,
    batch: str | None = None,
    collected_at=None,
    schema_version: int = 1,
    supersede: bool = True,
) -> dict:
    """
    Write a set of observations as one bitemporal transition.

    For each (subject, fact_key) in the incoming set we either:
      - skip it, when the current row has an identical content_hash
        (the fact has not changed, so there is nothing to record and the
        existing row keeps its original valid_from — this is what makes
        "unchanged since" answerable), or
      - close the current row at `collected_at` and insert the new value.

    Returns counts so the caller can write an honest batch summary.
    """
    collected_at = collected_at or now_datetime()
    recorded_at = now_datetime()

    rows = list(observations)
    if not rows:
        return {"inserted": 0, "unchanged": 0, "superseded": 0, "skipped": 0}

    prepared = []
    skipped = 0
    for o in rows:
        fact_key = (o.get("fact_key") or "").strip()
        subject = (o.get("subject") or o.get("asset") or "").strip()
        if not fact_key or not subject:
            skipped += 1
            continue
        value = o.get("value")
        vtext, vnum = _scalarise(value)
        prepared.append(
            {
                "client": client,
                "asset": o.get("asset"),
                "subject": subject[:255],
                "source": source[:64],
                "source_ref": (o.get("source_ref") or None),
                "fact_key": fact_key[:160],
                "value_json": json.dumps(value, separators=(",", ":"), default=str),
                "value_text": vtext,
                "value_num": vnum,
                "content_hash": content_hash(value),
                "confidence": int(o.get("confidence") or 100),
                "batch": batch,
                "schema_version": schema_version,
                "collected_at": collected_at,
            }
        )

    if not prepared:
        return {"inserted": 0, "unchanged": 0, "superseded": 0, "skipped": skipped}

    current = _current_hashes(client, [(p["subject"], p["fact_key"]) for p in prepared])

    to_insert = []
    unchanged = 0
    to_close = []
    for p in prepared:
        key = (p["subject"], p["fact_key"])
        existing = current.get(key)
        if existing and existing["content_hash"] == p["content_hash"]:
            unchanged += 1
            continue
        if existing and supersede:
            to_close.append(existing["id"])
        to_insert.append(p)

    if to_close:
        _close_rows(to_close, collected_at, recorded_at)

    _bulk_insert(to_insert, recorded_at)

    return {
        "inserted": len(to_insert),
        "unchanged": unchanged,
        "superseded": len(to_close),
        "skipped": skipped,
    }


def _current_hashes(client: str, keys: list[tuple[str, str]]) -> dict:
    """Fetch the open row id + hash for each (subject, fact_key) we are about
    to write. One query per chunk of subjects rather than one per row."""
    out: dict = {}
    subjects = sorted({k[0] for k in keys})
    facts = sorted({k[1] for k in keys})
    for i in range(0, len(subjects), 400):
        chunk = subjects[i : i + 400]
        rows = frappe.db.sql(
            f"""
            SELECT `id`, `subject`, `fact_key`, `content_hash`
            FROM `{TABLE}`
            WHERE `client` = %(client)s
              AND `valid_to` IS NULL
              AND `subject` IN %(subjects)s
              AND `fact_key` IN %(facts)s
            """,
            {"client": client, "subjects": chunk, "facts": facts},
            as_dict=True,
        )
        for r in rows:
            out[(r.subject, r.fact_key)] = {"id": r.id, "content_hash": r.content_hash}
    return out


def _close_rows(ids: list[int], valid_to, recorded_at) -> None:
    for i in range(0, len(ids), 1000):
        chunk = ids[i : i + 1000]
        frappe.db.sql(
            f"""
            UPDATE `{TABLE}`
            SET `valid_to` = %(valid_to)s
            WHERE `id` IN %(ids)s AND `valid_to` IS NULL
            """,
            {"valid_to": valid_to, "ids": chunk},
        )


_COLUMNS = (
    "client",
    "asset",
    "subject",
    "source",
    "source_ref",
    "fact_key",
    "value_json",
    "value_text",
    "value_num",
    "content_hash",
    "confidence",
    "batch",
    "schema_version",
    "collected_at",
    "recorded_at",
    "valid_from",
    "valid_to",
)


def _bulk_insert(rows: list[dict], recorded_at) -> None:
    if not rows:
        return
    cols = ", ".join(f"`{c}`" for c in _COLUMNS)
    placeholders = "(" + ", ".join(["%s"] * len(_COLUMNS)) + ")"

    for i in range(0, len(rows), INSERT_CHUNK):
        chunk = rows[i : i + INSERT_CHUNK]
        values: list = []
        for r in chunk:
            values.extend(
                [
                    r["client"],
                    r["asset"],
                    r["subject"],
                    r["source"],
                    r["source_ref"],
                    r["fact_key"],
                    r["value_json"],
                    r["value_text"],
                    r["value_num"],
                    r["content_hash"],
                    r["confidence"],
                    r["batch"],
                    r["schema_version"],
                    r["collected_at"],
                    recorded_at,
                    r["collected_at"],  # valid_from
                    None,  # valid_to — open
                ]
            )
        sql = f"INSERT INTO `{TABLE}` ({cols}) VALUES " + ", ".join([placeholders] * len(chunk))
        frappe.db.sql(sql, values)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def query(
    client: str,
    *,
    fact_keys: list[str] | None = None,
    subjects: list[str] | None = None,
    asset: str | None = None,
    source: str | None = None,
    as_of=None,
    limit: int = 10000,
) -> list[dict]:
    """
    Read observations. With `as_of` set, returns the facts that were believed
    true at that instant; without it, the current open set.
    """
    conditions = ["`client` = %(client)s"]
    params: dict = {"client": client, "limit": int(limit)}

    if as_of:
        conditions.append("`valid_from` <= %(as_of)s")
        conditions.append("(`valid_to` IS NULL OR `valid_to` > %(as_of)s)")
        params["as_of"] = as_of
    else:
        conditions.append("`valid_to` IS NULL")

    if fact_keys:
        conditions.append("`fact_key` IN %(fact_keys)s")
        params["fact_keys"] = list(fact_keys)
    if subjects:
        conditions.append("`subject` IN %(subjects)s")
        params["subjects"] = list(subjects)
    if asset:
        conditions.append("`asset` = %(asset)s")
        params["asset"] = asset
    if source:
        conditions.append("`source` = %(source)s")
        params["source"] = source

    rows = frappe.db.sql(
        f"""
        SELECT `id`, `client`, `asset`, `subject`, `source`, `source_ref`,
               `fact_key`, `value_json`, `value_text`, `value_num`,
               `confidence`, `collected_at`, `valid_from`, `valid_to`, `batch`
        FROM `{TABLE}`
        WHERE {' AND '.join(conditions)}
        ORDER BY `subject`, `fact_key`
        LIMIT %(limit)s
        """,
        params,
        as_dict=True,
    )
    for r in rows:
        try:
            r["value"] = json.loads(r["value_json"])
        except (TypeError, ValueError):
            r["value"] = r["value_json"]
    return rows


def subject_facts(client: str, subject: str, as_of=None) -> dict:
    """Collapse one subject's observations into a flat {fact_key: value} dict."""
    return {r["fact_key"]: r["value"] for r in query(client, subjects=[subject], as_of=as_of)}


def drift(client: str, since) -> list[dict]:
    """
    Facts that changed since `since`. Because supersession closes rows rather
    than overwriting them, drift is a range scan, not a re-scan of the estate.
    """
    return frappe.db.sql(
        f"""
        SELECT `subject`, `fact_key`, `source`, `value_text`, `valid_from`
        FROM `{TABLE}`
        WHERE `client` = %(client)s
          AND `valid_from` >= %(since)s
          AND `valid_to` IS NULL
        ORDER BY `valid_from` DESC
        LIMIT 5000
        """,
        {"client": client, "since": since},
        as_dict=True,
    )


def coverage(client: str) -> dict:
    """Counts used by the discovery-quality report and the cockpit tiles."""
    row = frappe.db.sql(
        f"""
        SELECT COUNT(*) AS facts,
               COUNT(DISTINCT `subject`) AS subjects,
               COUNT(DISTINCT `source`)  AS sources,
               MIN(`collected_at`)       AS oldest,
               MAX(`collected_at`)       AS newest
        FROM `{TABLE}`
        WHERE `client` = %(client)s AND `valid_to` IS NULL
        """,
        {"client": client},
        as_dict=True,
    )
    return row[0] if row else {}


def purge_raw(client: str, before) -> int:
    """
    Retention. Deletes closed (historical) rows older than `before`.
    Open rows are never purged here — a current fact has no expiry, it is
    superseded or it stands.
    """
    frappe.db.sql(
        f"""
        DELETE FROM `{TABLE}`
        WHERE `client` = %(client)s
          AND `valid_to` IS NOT NULL
          AND `valid_to` < %(before)s
        """,
        {"client": client, "before": before},
    )
    return frappe.db.sql("SELECT ROW_COUNT()")[0][0]
