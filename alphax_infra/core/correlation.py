# Copyright (c) 2026, Neotec Integrated Solutions
"""
Asset identity correlation.

Every source names the same machine differently. Entra ID knows a device by
its object GUID, Intune by its device ID, Azure by a resource ID, the AD
collector by a hardware UUID, and the network module only ever sees an IP.
Treating any single one of those as the identity produces either a duplicated
estate (inflating the denominator of every score) or a wrongly merged one
(hiding a real gap behind a compliant twin). Both are worse than an honest
"needs review".

So identifiers are weighted by how strongly they bind to one physical thing:

  authoritative   a globally unique, vendor-issued, stable id
  strong          unique in practice, occasionally recycled
  weak            frequently reassigned — never sufficient alone

The rule that matters: weak identifiers never establish identity on their own,
no matter how many of them agree. An IP plus a hostname is still a guess.
Anything below the auto-merge threshold becomes an Infra Merge Proposal for a
human, and the source records are always preserved so a merge is reversible.
"""

from __future__ import annotations

from dataclasses import dataclass

# identifier type -> (weight, tier)
IDENTIFIER_WEIGHTS = {
    # authoritative
    "azure_resource_id": (100, "authoritative"),
    "aws_arn": (100, "authoritative"),
    "entra_object_id": (100, "authoritative"),
    "intune_device_id": (95, "authoritative"),
    "ad_object_guid": (95, "authoritative"),
    "hardware_uuid": (90, "authoritative"),
    # strong
    "serial_number": (75, "strong"),
    "upn": (75, "strong"),
    "mail": (60, "strong"),
    "fqdn": (55, "strong"),
    "mac_address": (50, "strong"),
    # weak
    "hostname": (25, "weak"),
    "ip_address": (15, "weak"),
    "netbios_name": (15, "weak"),
}

AUTO_MERGE_THRESHOLD = 100
REVIEW_THRESHOLD = 40

# Two assets of genuinely different types are not the same thing even when a
# weak identifier collides. A VM and a firewall can share an IP after a
# re-address; they are not one asset.
INCOMPATIBLE_TYPES = True


@dataclass
class MatchScore:
    score: int = 0
    tiers: frozenset = frozenset()
    matched: tuple = ()

    @property
    def decision(self) -> str:
        has_authoritative = "authoritative" in self.tiers
        has_strong = "strong" in self.tiers
        if has_authoritative and self.score >= AUTO_MERGE_THRESHOLD:
            return "auto_merge"
        if (has_authoritative or has_strong) and self.score >= REVIEW_THRESHOLD:
            return "review"
        return "distinct"


def normalise(kind: str, value: str) -> str:
    """
    Canonical form for an identifier value. Case and separator differences are
    the usual cause of a false "no match" — a MAC from LLDP and the same MAC
    from an Intune record almost never arrive formatted identically.
    """
    v = (value or "").strip()
    if not v:
        return ""
    kind = (kind or "").lower()
    if kind == "mac_address":
        return "".join(c for c in v.lower() if c in "0123456789abcdef")
    if kind in ("hostname", "fqdn", "netbios_name", "upn", "mail"):
        return v.lower().rstrip(".")
    if kind in ("azure_resource_id", "aws_arn"):
        return v.lower()
    if kind in ("entra_object_id", "ad_object_guid", "intune_device_id", "hardware_uuid"):
        return v.lower().strip("{}")
    if kind == "serial_number":
        # Vendors pad, hyphenate and case serials inconsistently.
        cleaned = "".join(c for c in v.upper() if c.isalnum())
        # Values like "TO BE FILLED BY O.E.M." are placeholders, not identity.
        return "" if cleaned in _SERIAL_PLACEHOLDERS else cleaned
    return v


_SERIAL_PLACEHOLDERS = {
    "TOBEFILLEDBYOEM",
    "SYSTEMSERIALNUMBER",
    "DEFAULTSTRING",
    "NOTSPECIFIED",
    "NONE",
    "NA",
    "0",
    "123456789",
    "INVALID",
}


def score_match(left: list[dict], right: list[dict]) -> MatchScore:
    """
    Score two identifier sets. `left` and `right` are lists of
    {"identifier_type": ..., "identifier_value": ...}.
    """
    lmap: dict = {}
    for i in left:
        k = (i.get("identifier_type") or "").lower()
        v = normalise(k, i.get("identifier_value"))
        if v:
            lmap.setdefault(k, set()).add(v)

    score = 0
    tiers: set = set()
    matched: list = []

    for i in right:
        k = (i.get("identifier_type") or "").lower()
        v = normalise(k, i.get("identifier_value"))
        if not v or k not in lmap or v not in lmap[k]:
            continue
        weight, tier = IDENTIFIER_WEIGHTS.get(k, (10, "weak"))
        # Each identifier type contributes once, however many values collide.
        if k in (m[0] for m in matched):
            continue
        score += weight
        tiers.add(tier)
        matched.append((k, v))

    return MatchScore(score=min(score, 200), tiers=frozenset(tiers), matched=tuple(matched))


def find_candidates(client: str, identifiers: list[dict], *, exclude: str | None = None) -> list[dict]:
    """
    Find existing Infra Assets that share at least one identifier value.
    Indexed lookup on the child table rather than a scan of the estate.
    """
    import frappe

    pairs = []
    for i in identifiers:
        k = (i.get("identifier_type") or "").lower()
        v = normalise(k, i.get("identifier_value"))
        if v:
            pairs.append((k, v))
    if not pairs:
        return []

    rows = frappe.db.sql(
        """
        SELECT DISTINCT ident.parent AS asset
        FROM `tabInfra Asset Identifier` ident
        INNER JOIN `tabInfra Asset` a ON a.name = ident.parent
        WHERE a.client = %(client)s
          AND a.merged_into IS NULL
          AND (ident.identifier_type, ident.normalised_value) IN %(pairs)s
        LIMIT 50
        """,
        {"client": client, "pairs": pairs},
        as_dict=True,
    )
    return [r for r in rows if r.asset != exclude]


def correlate(client: str, incoming: dict) -> dict:
    """
    Resolve an incoming discovered asset to an existing one.

    `incoming` = {
        "asset_type": "Server",
        "asset_name": "...",
        "identifiers": [{"identifier_type": "...", "identifier_value": "..."}],
    }

    Returns {"action": auto_merge|review|create, "asset": name|None, "score": n}.
    The caller decides what to do; this function never writes.
    """
    import frappe

    identifiers = incoming.get("identifiers") or []
    candidates = find_candidates(client, identifiers)
    if not candidates:
        return {"action": "create", "asset": None, "score": 0, "matched": []}

    best = None
    for c in candidates:
        existing = frappe.get_all(
            "Infra Asset Identifier",
            filters={"parent": c.asset},
            fields=["identifier_type", "identifier_value"],
        )
        ms = score_match(existing, identifiers)

        if INCOMPATIBLE_TYPES and incoming.get("asset_type"):
            other_type = frappe.db.get_value("Infra Asset", c.asset, "asset_type")
            if other_type and other_type != incoming["asset_type"] and "authoritative" not in ms.tiers:
                # Weak/strong agreement across different asset types is a
                # collision, not an identity.
                continue

        if best is None or ms.score > best[1].score:
            best = (c.asset, ms)

    if best is None:
        return {"action": "create", "asset": None, "score": 0, "matched": []}

    asset, ms = best
    decision = ms.decision
    return {
        "action": "create" if decision == "distinct" else decision,
        "asset": None if decision == "distinct" else asset,
        "score": ms.score,
        "tiers": sorted(ms.tiers),
        "matched": [f"{k}={v}" for k, v in ms.matched],
    }


def confidence_for(identifiers: list[dict]) -> int:
    """
    How much we trust that this asset record refers to one real thing. Used
    for the "inventory confidence" tile and to hold low-confidence assets out
    of scoring denominators until reviewed.
    """
    best_tier = "weak"
    total = 0
    seen: set = set()
    for i in identifiers:
        k = (i.get("identifier_type") or "").lower()
        if k in seen or not normalise(k, i.get("identifier_value")):
            continue
        seen.add(k)
        weight, tier = IDENTIFIER_WEIGHTS.get(k, (10, "weak"))
        total += weight
        if tier == "authoritative":
            best_tier = "authoritative"
        elif tier == "strong" and best_tier != "authoritative":
            best_tier = "strong"

    if best_tier == "authoritative":
        return min(100, 80 + total // 20)
    if best_tier == "strong":
        return min(75, 45 + total // 5)
    return min(40, 10 + total)
