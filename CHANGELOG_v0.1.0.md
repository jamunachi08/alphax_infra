# AlphaX Infra — v0.1.0

First release. Frappe/ERPNext v15. Requires `alphax_grc`.

## Scope of this release

Agentless discovery against Microsoft Entra ID, Intune and Azure; a bitemporal
observation store; a declarative check engine; asset correlation; and write-back
into AlphaX GRC evidence and findings. The collector ingest API is complete and
tested; the collector binary itself is not in this release.

## Added

**Core engines** (`alphax_infra/core/`, all importable without a Frappe site)
- `canonical.py` — RFC 8785 JCS canonical JSON, SHA-256 batch digests, Ed25519
  verification via `cryptography` with a pure-Python RFC 8032 fallback, and
  envelope validation. Signing a non-canonical form is the usual cause of
  intermittent ingest rejections; this removes that class of failure.
- `observations.py` — bitemporal store on `__infra_observation`, a non-DocType
  InnoDB table. Content-hash deduplication, supersession by row closure,
  chunked bulk insert, point-in-time and drift queries, retention purge.
- `rules.py` — declarative `select` / `predicate` / `aggregate` engine. Twenty
  leaf operators, boolean combinators, dotted fact traversal, six aggregate
  modes. No `eval`, `exec` or `compile` anywhere.
- `correlation.py` — weighted identity matching across authoritative, strong
  and weak identifier tiers. Weak identifiers never establish identity alone.
- `tenancy.py` — scope resolution that fails closed to `1=0`, cross-tenant
  access gated behind an explicit role and logged on every use.
- `grc_bridge.py` — evidence, finding and asset-inventory write-back through
  the public document API only, resolving Select options against live meta.

**Connectors** — Entra ID (identity posture, privileged roles, Conditional
Access, app credential expiry), M365/Intune (device compliance, encryption,
jailbreak, check-in freshness), Azure (resource inventory, NSG internet
exposure, storage posture, diagnostic logging). All read-only. Secrets are
redacted on the way in, not on the way out.

**Content** — 32 checks mapped to ISO/IEC 27001:2022 Annex A control identifiers
and NCA ECC-2:2024 references. 7 Critical, 15 High, 9 Medium, 1 Low.

**DocTypes** — 15: settings, connector (+ scope child), collector, discovery job,
discovery batch, asset (+ identifier child), asset relationship, merge proposal,
check, check result, assessment session, consent record, access log.

**API** — collector enrolment with single-use hashed tokens, signed batch upload
behind a seven-step acceptance chain (active collector → valid envelope →
approved module → replay window → strictly increasing sequence → unseen content
hash → signature verification), heartbeat, and the customer-facing assessment
session with named consent.

**Operations** — idempotent installer shared by install and migrate, scheduled
connector runs and daily evaluation, consent and session expiry, stale-collector
and critical-failure alerting, optional retention purge, and a deletion guard
that refuses to orphan an evidence chain.

**Guards and tests** — `verify_tree.py` with 17 check groups running without a
site or database; `tests/test_offline.py` with 311 assertions across 9 suites;
`tests/test_integration.py` for the store, tenancy, checks and ingest.

## Defects found and fixed during this build

Recorded because they are the kind that ship silently:

- **Predicate soundness.** An unknown operator returned `False` instead of
  raising whenever the referenced fact happened to be absent, so a typo in a
  content pack would have looked like a clean control failure rather than a
  defect. Operator validation now runs before the missing-fact shortcut.
- **Tenancy gap.** `Infra Check` carried a `client` field but was missing from
  `permission_query_conditions`, so its list views and exports would not have
  been tenant-filtered while the API was. Caught by `verify_tree.py`.
- **Ungreppable fact keys.** The Intune connector built compliance-policy fact
  keys with a runtime snake-caser, making them invisible to the catalogue
  cross-check and liable to disappear silently on a Microsoft attribute rename.
  Replaced with an explicit mapping.
- **Testability.** `rules.py` and `correlation.py` imported `frappe` at module
  scope, so neither CI nor the guard could validate the shipped catalogue.
  Frappe-dependent imports moved to their call sites.

## Known limitations

No collector binary, no report templates, no assessor cockpit, no on-premises
collection. 32 checks is identity-weighted and is not a complete ISO 27001 or
NCA ECC assessment. Control mappings propose evidence reuse; they do not prove
the target control.

## Upgrade notes

New install. `bench --site <site> install-app alphax_infra` after `alphax_grc`,
then `bench --site <site> migrate`. The observation table, roles and check
catalogue are created idempotently on both install and migrate. Existing checks
are never overwritten by a migration, so client-tuned thresholds survive.
