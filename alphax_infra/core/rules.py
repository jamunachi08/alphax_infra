# Copyright (c) 2026, Neotec Integrated Solutions
"""
The check engine.

A check is data, not code. That is the whole point: connector packs and
content packs are only sellable if a new check ships as a JSON row reviewed by
a compliance specialist, not as a Python patch reviewed by an engineer.

A check has three parts:

  select     which observations it looks at (fact keys, source, asset type)
  predicate  a boolean expression tree evaluated per subject
  aggregate  how per-subject results roll up into one pass/fail verdict

Every evaluation returns the failing subjects, so a finding can name exactly
which accounts or resources caused it, and a reviewer can sample them. A check
that cannot find any observations in scope returns Inconclusive rather than
Pass — silently passing a control because nothing was collected is the single
most dangerous failure mode a compliance product can have.

There is no eval(), no exec() and no template rendering anywhere in this
module. Predicate trees are walked explicitly, and an unknown operator raises
rather than defaulting to true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

try:  # pragma: no cover - exercised by whichever branch the environment gives
    from frappe.utils import add_days, get_datetime, now_datetime
except ImportError:
    # The engine is pure logic and is deliberately importable without a
    # Frappe site, so verify_tree.py and the unit tests can validate every
    # shipped check definition in CI without standing up a bench.
    from datetime import datetime as _dt, timedelta as _td

    def now_datetime():
        return _dt.now()

    def add_days(base, days):
        return (base if isinstance(base, _dt) else _dt.now()) + _td(days=days)

    def get_datetime(value):
        if isinstance(value, _dt):
            return value
        text = str(value).strip().replace("Z", "+00:00")
        parsed = _dt.fromisoformat(text)
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

PASS = "Pass"
FAIL = "Fail"
INCONCLUSIVE = "Inconclusive"
NOT_APPLICABLE = "Not Applicable"


class CheckDefinitionError(Exception):
    """Raised for a malformed check. Surfaced at save time, not at run time."""


@dataclass
class CheckResult:
    verdict: str = INCONCLUSIVE
    total: int = 0
    passed: int = 0
    failed: int = 0
    failing_subjects: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        return round(100.0 * self.passed / self.total, 2) if self.total else 0.0

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": self.pass_rate,
            # Capped: a finding needs a representative sample, not 40k rows.
            "failing_subjects": self.failing_subjects[:200],
            "failing_subject_count": len(self.failing_subjects),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

_MISSING = object()

# Every leaf operator the engine understands. Kept as an explicit set so an
# unknown operator is a hard error rather than a silent false.
_LEAF_OPS = frozenset({
    "eq", "equals", "ne", "not_equals",
    "gt", "gte", "lt", "lte",
    "in", "not_in",
    "contains", "not_contains",
    "empty", "not_empty",
    "matches",
    "older_than_days", "newer_than_days",
    "count_gte", "count_lte",
})


def _resolve(facts: dict, path: str):
    """
    Look up `path` in a subject's facts. Supports dotted traversal into the
    decoded JSON value, so a check can address `mfa.methods.strong` when the
    collector recorded `mfa` as a nested object.
    """
    if path in facts:
        return facts[path]
    head, _, rest = path.partition(".")
    if head not in facts:
        return _MISSING
    cur = facts[head]
    for part in rest.split(".") if rest else []:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _as_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str) and value.strip():
        try:
            return get_datetime(value)
        except Exception:  # noqa: BLE001
            return None
    return None


def _cmp_numeric(left, right, op) -> bool:
    try:
        lf, rf = float(left), float(right)
    except (TypeError, ValueError):
        return False
    return op(lf, rf)


def evaluate_predicate(node: dict, facts: dict, *, now=None) -> bool:
    """Walk a predicate tree against one subject's facts."""
    if not isinstance(node, dict):
        raise CheckDefinitionError("predicate node must be an object")

    op = node.get("op")
    if not op:
        raise CheckDefinitionError("predicate node is missing 'op'")
    op = str(op).lower()
    now = now or now_datetime()

    # --- boolean combinators ---
    if op == "and":
        children = node.get("of") or []
        if not children:
            raise CheckDefinitionError("'and' requires a non-empty 'of'")
        return all(evaluate_predicate(c, facts, now=now) for c in children)
    if op == "or":
        children = node.get("of") or []
        if not children:
            raise CheckDefinitionError("'or' requires a non-empty 'of'")
        return any(evaluate_predicate(c, facts, now=now) for c in children)
    if op == "not":
        inner = node.get("of")
        if not isinstance(inner, dict):
            raise CheckDefinitionError("'not' requires a single 'of' object")
        return not evaluate_predicate(inner, facts, now=now)

    # --- leaf operators ---
    fact = node.get("fact")
    if not fact:
        raise CheckDefinitionError(f"operator '{op}' requires 'fact'")
    actual = _resolve(facts, fact)
    expected = node.get("value")

    if op == "exists":
        return actual is not _MISSING
    if op == "missing":
        return actual is _MISSING

    # The operator is validated before the missing-fact shortcut below.
    # Checking it afterwards meant a typo'd operator returned False whenever
    # the fact happened to be absent, so a malformed check in a content pack
    # would look like a clean failure rather than a defect. An unknown
    # operator must always raise, whatever the data looks like.
    if op not in _LEAF_OPS:
        raise CheckDefinitionError(f"unknown predicate operator: {op}")

    if actual is _MISSING:
        # A comparison against an absent fact is false, never true. The
        # aggregate layer decides whether absence means Fail or Inconclusive.
        return False

    if op in ("eq", "equals"):
        if isinstance(expected, bool) or isinstance(actual, bool):
            return bool(actual) is bool(expected)
        return actual == expected
    if op in ("ne", "not_equals"):
        return actual != expected
    if op == "gt":
        return _cmp_numeric(actual, expected, lambda a, b: a > b)
    if op == "gte":
        return _cmp_numeric(actual, expected, lambda a, b: a >= b)
    if op == "lt":
        return _cmp_numeric(actual, expected, lambda a, b: a < b)
    if op == "lte":
        return _cmp_numeric(actual, expected, lambda a, b: a <= b)
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op == "contains":
        if isinstance(actual, (list, tuple)):
            return expected in actual
        return str(expected) in str(actual)
    if op == "not_contains":
        if isinstance(actual, (list, tuple)):
            return expected not in actual
        return str(expected) not in str(actual)
    if op == "empty":
        return actual in (None, "", [], {})
    if op == "not_empty":
        return actual not in (None, "", [], {})
    if op == "matches":
        try:
            return bool(re.search(str(expected), str(actual)))
        except re.error as exc:
            raise CheckDefinitionError(f"invalid regex in check: {exc}") from exc
    if op == "older_than_days":
        dt = _as_datetime(actual)
        if dt is None:
            return False
        return dt < get_datetime(add_days(now, -int(expected or 0)))
    if op == "newer_than_days":
        dt = _as_datetime(actual)
        if dt is None:
            return False
        return dt >= get_datetime(add_days(now, -int(expected or 0)))
    if op == "count_gte":
        return isinstance(actual, (list, tuple, dict)) and len(actual) >= int(expected or 0)
    if op == "count_lte":
        return isinstance(actual, (list, tuple, dict)) and len(actual) <= int(expected or 0)

    raise CheckDefinitionError(f"unknown predicate operator: {op}")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

AGGREGATES = (
    "all_must_pass",
    "none_must_pass",
    "count_at_least",
    "count_at_most",
    "ratio_at_least",
    "exists_one",
)


def aggregate(mode: str, passed: int, failed: int, threshold: float) -> str:
    total = passed + failed
    if not total:
        return INCONCLUSIVE
    mode = (mode or "all_must_pass").lower()

    if mode == "all_must_pass":
        return PASS if failed == 0 else FAIL
    if mode == "none_must_pass":
        return PASS if passed == 0 else FAIL
    if mode == "exists_one":
        return PASS if passed >= 1 else FAIL
    if mode == "count_at_least":
        return PASS if passed >= threshold else FAIL
    if mode == "count_at_most":
        return PASS if passed <= threshold else FAIL
    if mode == "ratio_at_least":
        return PASS if (100.0 * passed / total) >= threshold else FAIL

    raise CheckDefinitionError(f"unknown aggregate mode: {mode}")


# ---------------------------------------------------------------------------
# Running a check
# ---------------------------------------------------------------------------


def validate_definition(definition: dict) -> list[str]:
    """Static validation, run on save so a broken check never reaches a run."""
    problems: list[str] = []
    if not isinstance(definition, dict):
        return ["check definition must be an object"]

    select = definition.get("select") or {}
    if not isinstance(select, dict):
        problems.append("'select' must be an object")
    elif not select.get("fact_keys"):
        problems.append("'select.fact_keys' is required — a check must declare what it reads")

    predicate = definition.get("predicate")
    if not isinstance(predicate, dict):
        problems.append("'predicate' must be an object")
    else:
        try:
            evaluate_predicate(predicate, {"__probe__": None})
        except CheckDefinitionError as exc:
            problems.append(str(exc))
        except Exception:  # noqa: BLE001 — runtime type errors on the probe are fine
            pass

    mode = (definition.get("aggregate") or "all_must_pass").lower()
    if mode not in AGGREGATES:
        problems.append(f"'aggregate' must be one of: {', '.join(AGGREGATES)}")

    return problems


def run_check(definition: dict, client: str, *, as_of=None) -> CheckResult:
    """
    Evaluate one check for one client.

    `as_of` runs the check against the estate as it was believed at that
    instant, which is how a check is re-run for an audit period without
    depending on data that arrived afterwards.
    """
    problems = validate_definition(definition)
    if problems:
        raise CheckDefinitionError("; ".join(problems))

    # Imported here rather than at module scope: the store needs a Frappe
    # site, the predicate layer does not. Keeping the dependency at the call
    # site is what lets verify_tree.py and the unit tests validate every
    # shipped check definition in CI without a bench.
    from alphax_infra.core import observations as obs

    select = definition["select"]
    fact_keys = list(select["fact_keys"])
    rows = obs.query(
        client,
        fact_keys=fact_keys,
        source=select.get("source"),
        as_of=as_of,
        limit=int(select.get("limit") or 50000),
    )

    result = CheckResult()
    if not rows:
        result.verdict = INCONCLUSIVE
        result.detail = {
            "reason": "no observations in scope",
            "fact_keys": fact_keys,
            "source": select.get("source"),
            "as_of": str(as_of) if as_of else None,
        }
        return result

    # Group facts by subject.
    by_subject: dict = {}
    for r in rows:
        by_subject.setdefault(r["subject"], {})[r["fact_key"]] = r["value"]

    # An optional scope filter narrows which subjects the check applies to,
    # which is how "privileged accounts only" is expressed without a second
    # fact key.
    scope = select.get("scope")
    now = now_datetime()
    subjects = list(by_subject.items())
    if scope:
        subjects = [(s, f) for s, f in subjects if evaluate_predicate(scope, f, now=now)]
        if not subjects:
            result.verdict = NOT_APPLICABLE
            result.detail = {"reason": "no subjects matched the scope filter"}
            return result

    predicate = definition["predicate"]
    require_all_facts = bool(select.get("require_all_facts"))

    incomplete = 0
    for subject, facts in subjects:
        if require_all_facts and not all(k in facts for k in fact_keys):
            incomplete += 1
            continue
        if evaluate_predicate(predicate, facts, now=now):
            result.passed += 1
        else:
            result.failed += 1
            result.failing_subjects.append(subject)

    result.total = result.passed + result.failed

    if not result.total:
        result.verdict = INCONCLUSIVE
        result.detail = {
            "reason": "every subject in scope was missing required facts",
            "incomplete_subjects": incomplete,
        }
        return result

    result.verdict = aggregate(
        definition.get("aggregate"),
        result.passed,
        result.failed,
        float(definition.get("threshold") or 0),
    )
    result.detail = {
        "aggregate": definition.get("aggregate") or "all_must_pass",
        "threshold": definition.get("threshold"),
        "subjects_evaluated": result.total,
        "subjects_incomplete": incomplete,
        "as_of": str(as_of) if as_of else None,
    }
    return result
