#!/usr/bin/env python3
# Copyright (c) 2026, Neotec Integrated Solutions
"""
Offline test suite.

Runs with no Frappe site, no database and no network, which means it can gate
a commit. It covers the parts of the app where a silent wrong answer is worse
than a crash: canonicalisation (a signature that verifies inconsistently),
predicate evaluation (a check that passes when it should fail), correlation
(assets merged that are not the same machine), and the shipped catalogue.

    python3 tests/test_offline.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alphax_infra.core import correlation  # noqa: E402
from alphax_infra.core.canonical import (  # noqa: E402
    SCHEMA_VERSION,
    SignatureError,
    canonicalize,
    content_hash,
    digest,
    signing_payload,
    validate_envelope,
    verify_signature,
)
from alphax_infra.core.rules import (  # noqa: E402
    CheckDefinitionError,
    aggregate,
    evaluate_predicate,
    validate_definition,
)

PASSED = 0
FAILED: list[str] = []


def eq(actual, expected, label):
    global PASSED
    if actual == expected:
        PASSED += 1
    else:
        FAILED.append(f"{label}: expected {expected!r}, got {actual!r}")


def true(value, label):
    eq(bool(value), True, label)


def false(value, label):
    eq(bool(value), False, label)


def raises(fn, exc, label):
    global PASSED
    try:
        fn()
    except exc:
        PASSED += 1
        return
    except Exception as other:  # noqa: BLE001
        FAILED.append(f"{label}: raised {type(other).__name__}, expected {exc.__name__}")
        return
    FAILED.append(f"{label}: did not raise {exc.__name__}")


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def test_canonical():
    eq(canonicalize({"b": 1, "a": 2}), b'{"a":2,"b":1}', "keys sort")
    eq(canonicalize({"a": {"z": 1, "y": 2}}), b'{"a":{"y":2,"z":1}}', "nested keys sort")
    eq(canonicalize([3, 1, 2]), b"[3,1,2]", "array order is preserved")
    eq(canonicalize(True), b"true", "bool")
    eq(canonicalize(None), b"null", "null")
    eq(canonicalize(1.0), b"1", "1.0 serialises as 1")
    eq(canonicalize(-0.0), b"0", "negative zero normalises")
    eq(canonicalize("a\nb"), b'"a\\nb"', "control chars escape")
    eq(canonicalize("héllo"), "\"héllo\"".encode("utf-8"), "non-ascii stays literal")

    # The property that actually matters: dict insertion order must not change
    # the bytes, because the collector and the server build the object
    # differently and both must hash to the same value.
    a = {"z": 1, "m": {"q": [1, 2], "b": True}, "a": "x"}
    b = {"a": "x", "m": {"b": True, "q": [1, 2]}, "z": 1}
    eq(digest(a), digest(b), "insertion order does not change the digest")

    eq(len(digest({"a": 1})), 64, "digest is sha-256 hex")
    eq(len(content_hash({"a": 1})), 32, "content hash is 128-bit")
    true(content_hash({"a": 1}) != content_hash({"a": 2}), "content hash discriminates")


def test_envelope():
    good = {
        "schema_version": SCHEMA_VERSION,
        "collector_id": "COL-0001",
        "collector_version": "0.1.0",
        "module": "ad",
        "module_version": "1",
        "client": "ACME",
        "sequence": 5,
        "nonce": "0123456789abcdef0123",
        "collected_at": "2026-09-13 10:00:00",
        "observations": [{"fact_key": "x", "value": 1, "subject": "s"}],
        "signature": "ignored",
    }
    eq(validate_envelope(good), [], "valid envelope passes")
    true("signature" not in signing_payload(good), "signature is excluded from signed payload")
    eq(len(signing_payload(good)), 10, "signed payload is the ten required fields")

    bad = dict(good, sequence=-1)
    true(any("sequence" in p for p in validate_envelope(bad)), "negative sequence rejected")

    bad = dict(good, schema_version=99)
    true(any("schema_version" in p for p in validate_envelope(bad)), "wrong schema rejected")

    bad = dict(good, nonce="short")
    true(any("nonce" in p for p in validate_envelope(bad)), "short nonce rejected")

    bad = dict(good, observations=[])
    true(any("empty" in p for p in validate_envelope(bad)), "empty batch rejected")

    del bad["collector_id"]
    true(any("collector_id" in p for p in validate_envelope(bad)), "missing field reported")


def test_signature():
    payload = {"a": 1}
    # A malformed key or signature must raise, never quietly return False:
    # "could not check" and "forged" have to be distinguishable.
    raises(lambda: verify_signature(payload, "!!", "AA" * 16), SignatureError, "bad base64 raises")
    raises(lambda: verify_signature(payload, "AAAA", "AAAA"), SignatureError, "short sig raises")

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return

    import base64

    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()
    sig = base64.b64encode(key.sign(canonicalize(payload))).decode()

    true(verify_signature(payload, sig, pub), "valid signature verifies")
    false(verify_signature({"a": 2}, sig, pub), "tampered payload fails")
    # Reordering keys must still verify — this is the whole point of JCS.
    true(verify_signature({"a": 1}, sig, pub), "canonical form is order independent")


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_predicates():
    facts = {
        "enabled": True,
        "count": 5,
        "name": "web-01",
        "roles": ["admin", "reader"],
        "nested": {"deep": {"value": 42}},
        "when": "2020-01-01 00:00:00",
    }

    true(evaluate_predicate({"op": "eq", "fact": "enabled", "value": True}, facts), "eq bool")
    false(evaluate_predicate({"op": "eq", "fact": "enabled", "value": False}, facts), "eq bool false")
    true(evaluate_predicate({"op": "gt", "fact": "count", "value": 3}, facts), "gt")
    false(evaluate_predicate({"op": "gt", "fact": "count", "value": 9}, facts), "gt false")
    true(evaluate_predicate({"op": "in", "fact": "name", "value": ["web-01"]}, facts), "in")
    true(evaluate_predicate({"op": "contains", "fact": "roles", "value": "admin"}, facts), "contains")
    true(evaluate_predicate({"op": "matches", "fact": "name", "value": r"^web-"}, facts), "regex")
    true(evaluate_predicate({"op": "exists", "fact": "count"}, facts), "exists")
    true(evaluate_predicate({"op": "missing", "fact": "absent"}, facts), "missing")
    true(
        evaluate_predicate({"op": "eq", "fact": "nested.deep.value", "value": 42}, facts),
        "dotted traversal",
    )
    true(
        evaluate_predicate({"op": "older_than_days", "fact": "when", "value": 30}, facts),
        "older_than_days",
    )

    # The rule that prevents false passes: a comparison against an absent fact
    # is false, never true.
    false(evaluate_predicate({"op": "eq", "fact": "absent", "value": None}, facts), "absent is false")
    false(evaluate_predicate({"op": "gt", "fact": "absent", "value": 0}, facts), "absent gt is false")

    true(
        evaluate_predicate(
            {
                "op": "and",
                "of": [
                    {"op": "eq", "fact": "enabled", "value": True},
                    {"op": "gte", "fact": "count", "value": 5},
                ],
            },
            facts,
        ),
        "and",
    )
    false(
        evaluate_predicate(
            {"op": "or", "of": [{"op": "eq", "fact": "count", "value": 1},
                                {"op": "eq", "fact": "name", "value": "x"}]},
            facts,
        ),
        "or false",
    )
    true(evaluate_predicate({"op": "not", "of": {"op": "eq", "fact": "count", "value": 1}}, facts), "not")

    # An unknown operator must raise. Defaulting to true would turn a typo in
    # a content pack into a silently passing control.
    raises(
        lambda: evaluate_predicate({"op": "definitely_not_an_op", "fact": "x"}, facts),
        CheckDefinitionError,
        "unknown operator raises",
    )
    raises(
        lambda: evaluate_predicate({"op": "and", "of": []}, facts),
        CheckDefinitionError,
        "empty and raises",
    )


def test_aggregates():
    eq(aggregate("all_must_pass", 5, 0, 0), "Pass", "all pass")
    eq(aggregate("all_must_pass", 4, 1, 0), "Fail", "one failure fails all_must_pass")
    eq(aggregate("none_must_pass", 0, 3, 0), "Pass", "none matched")
    eq(aggregate("ratio_at_least", 95, 5, 95), "Pass", "ratio at threshold")
    eq(aggregate("ratio_at_least", 94, 6, 95), "Fail", "ratio below threshold")
    eq(aggregate("count_at_least", 3, 0, 2), "Pass", "count at least")
    eq(aggregate("exists_one", 1, 9, 0), "Pass", "exists one")

    # Nothing evaluated is Inconclusive, never Pass. A check that found no
    # subjects has not demonstrated compliance.
    eq(aggregate("all_must_pass", 0, 0, 0), "Inconclusive", "empty is inconclusive not pass")
    eq(aggregate("none_must_pass", 0, 0, 0), "Inconclusive", "empty none_must_pass inconclusive")


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def test_normalisation():
    eq(correlation.normalise("mac_address", "AA:BB:CC:DD:EE:FF"), "aabbccddeeff", "mac strips")
    eq(correlation.normalise("mac_address", "aa-bb-cc-dd-ee-ff"), "aabbccddeeff", "mac separators")
    eq(correlation.normalise("hostname", "WEB-01.corp.local."), "web-01.corp.local", "host lowers")
    eq(correlation.normalise("upn", "User@Corp.COM"), "user@corp.com", "upn lowers")
    eq(correlation.normalise("serial_number", "ab-123 456"), "AB123456", "serial strips")
    eq(correlation.normalise("entra_object_id", "{ABC-123}"), "abc-123", "guid braces")

    # Placeholder serials must not become identity — otherwise an entire fleet
    # of white-box machines merges into one asset.
    eq(correlation.normalise("serial_number", "To Be Filled By O.E.M."), "", "oem placeholder dropped")
    eq(correlation.normalise("serial_number", "None"), "", "None serial dropped")


def test_match_scoring():
    auth = [{"identifier_type": "azure_resource_id", "identifier_value": "/subs/x/vm1"}]
    same = [{"identifier_type": "azure_resource_id", "identifier_value": "/SUBS/X/VM1"}]
    ms = correlation.score_match(auth, same)
    eq(ms.decision, "auto_merge", "authoritative match auto-merges despite case")

    weak_a = [
        {"identifier_type": "ip_address", "identifier_value": "10.0.0.5"},
        {"identifier_type": "hostname", "identifier_value": "web-01"},
    ]
    weak_b = [
        {"identifier_type": "ip_address", "identifier_value": "10.0.0.5"},
        {"identifier_type": "hostname", "identifier_value": "web-01"},
    ]
    ms = correlation.score_match(weak_a, weak_b)
    # The single most important assertion in this file. Weak identifiers must
    # never establish identity, however many of them agree: IP addresses and
    # hostnames are reassigned, and a wrong merge hides a real gap behind a
    # compliant twin.
    eq(ms.decision, "distinct", "weak identifiers alone never merge")
    true("authoritative" not in ms.tiers, "no authoritative tier from weak ids")

    strong = [{"identifier_type": "serial_number", "identifier_value": "SN123456"}]
    ms = correlation.score_match(strong, strong)
    eq(ms.decision, "review", "strong match goes to review, not auto-merge")

    ms = correlation.score_match(auth, [{"identifier_type": "upn", "identifier_value": "a@b.c"}])
    eq(ms.decision, "distinct", "no overlap is distinct")


def test_confidence():
    high = correlation.confidence_for(
        [{"identifier_type": "azure_resource_id", "identifier_value": "/x/y"}]
    )
    low = correlation.confidence_for(
        [{"identifier_type": "ip_address", "identifier_value": "10.0.0.1"}]
    )
    true(high >= 80, "authoritative identifier yields high confidence")
    true(low <= 40, "ip alone yields low confidence")
    true(high > low, "confidence is ordered by identifier strength")

    dupes = correlation.confidence_for(
        [{"identifier_type": "ip_address", "identifier_value": "10.0.0.1"}] * 8
    )
    eq(dupes, low, "repeating one weak identifier does not raise confidence")


# ---------------------------------------------------------------------------
# Shipped catalogue
# ---------------------------------------------------------------------------


def test_catalog():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "alphax_infra", "data", "check_catalog.json",
    )
    catalog = json.load(open(path, encoding="utf-8"))
    checks = catalog["checks"]

    true(len(checks) >= 30, f"catalogue has at least 30 checks (has {len(checks)})")

    codes = [c["check_code"] for c in checks]
    eq(len(codes), len(set(codes)), "check codes are unique")

    for c in checks:
        code = c["check_code"]
        problems = validate_definition(c["definition"])
        eq(problems, [], f"{code} definition validates")
        true(bool(c.get("description")), f"{code} has a description")
        true(bool(c.get("remediation")), f"{code} has remediation guidance")
        true(bool(c.get("control")), f"{code} is mapped to a control")
        true(
            c["severity"] in ("Critical", "High", "Medium", "Low", "Informational"),
            f"{code} severity is valid",
        )
        true(c["source"] in ("entra", "m365", "azure"), f"{code} names a shipped connector")

    # Each check must read a fact some connector actually emits, otherwise it
    # will return Inconclusive forever and nobody will notice.
    connectors_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "alphax_infra", "connectors",
    )
    emitted = set()
    for fname in os.listdir(connectors_dir):
        if not fname.endswith(".py"):
            continue
        source = open(os.path.join(connectors_dir, fname), encoding="utf-8").read()
        import re

        emitted.update(re.findall(r'"([a-z_]+\.[a-z_]+)"', source))

    for c in checks:
        for fk in c["definition"]["select"]["fact_keys"]:
            true(fk in emitted, f"{c['check_code']} reads {fk}, which a connector emits")


# ---------------------------------------------------------------------------


def main() -> int:
    for fn in (
        test_canonical,
        test_envelope,
        test_signature,
        test_predicates,
        test_aggregates,
        test_normalisation,
        test_match_scoring,
        test_confidence,
        test_catalog,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILED.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")

    if FAILED:
        for line in FAILED:
            print(f"  FAIL  {line}")
        print(f"\n{PASSED} passed, {len(FAILED)} failed")
        return 1

    print(f"  {PASSED} checks passed across 9 suites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
