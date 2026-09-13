# AlphaX Infra

IT infrastructure discovery and control assessment, built as a companion app to
[AlphaX GRC](https://github.com/jamunachi08). Agentless collection from
Microsoft Entra ID, Intune and Azure turns tenant configuration into
timestamped, re-runnable evidence against the control library that already
exists in your GRC deployment.

**Version 0.1.1** — Frappe/ERPNext v15. Requires `alphax_grc`.

---

## What it does

Discovery runs read-only against a customer's cloud tenant and write normalised
*observations*. Checks — which are data, not code — evaluate those observations
and produce verdicts. Failed checks become GRC findings; all verdicts become GRC
evidence. Nothing is marked compliant without a human.

The commercial argument is narrow and specific: on a typical KSA mid-market
tenant, three read-only connectors satisfy a meaningful share of the
access-control, endpoint and cloud-configuration evidence requests in an ISO
27001 or NCA ECC engagement, with no agent, no inbound firewall change, and a
credential the customer can revoke from their own portal.

## Install

```bash
bench get-app alphax_grc   https://github.com/jamunachi08/alphax_grc
bench get-app alphax_infra https://github.com/jamunachi08/alphax_infra

bench --site your.site install-app alphax_grc
bench --site your.site install-app alphax_infra
bench --site your.site migrate
```

`alphax_grc` is a hard dependency and the installer refuses to proceed without
it. This app does not carry its own control library, evidence model or client
register — it extends the ones already in GRC, so you maintain one control
library rather than two that drift.

## First run

Order matters, and the app enforces it:

1. **Record consent.** `Infra Consent Record` — a named, authorised person at
   the customer, the sources they authorised, and the exact wording they agreed
   to (hashed, so it is provable later). A connector cannot be enabled without
   an Active consent record.
2. **Configure a connector.** `Infra Connector` — tenant ID, app registration,
   client secret. The secret goes to Frappe's encrypted password store and is
   never written to observations, logs or reports. Use **Test Connection** to
   authenticate without fetching anything.
3. **Approve scopes.** Every requested permission is read-only and is listed for
   per-scope approval on the connector.
4. **Run discovery.** Manual or scheduled. Watch `Infra Discovery Job`.
5. **Review merge proposals.** Anything below the auto-merge threshold waits for
   a human. Rejecting one requires a rationale.
6. **Evaluate checks**, then review the findings in GRC.

### Required app registration permissions

All read-only. A connector requesting write access is a defect, not a feature.

| Connector | Permissions |
|---|---|
| Entra ID | `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory` |
| M365 / Intune | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Device.Read.All`, `Directory.Read.All` |
| Azure | `Reader` on the subscription, `Key Vault Reader` where vaults are in scope |

## Architecture decisions worth knowing

**Observations are not a DocType.** They live in `__infra_observation`, a plain
InnoDB table the ORM never touches. A pilot tenant produces ~100k observations
per cycle; writing those through `frappe.get_doc().insert()` would cost a
controller instantiation, a naming round trip and a version row each, turning a
two-minute ingest into an hour and filling `tabVersion` with noise. Observations
are machine facts — never hand-edited, never workflowed.

**The store is bitemporal from day one.** Every fact carries `collected_at`,
`recorded_at`, `valid_from` and `valid_to`. Superseding a fact closes the old
row rather than updating it, so "what was true on 30 September" is a `WHERE`
clause rather than a frozen PDF you have to trust. This cannot be retrofitted —
you would be reconstructing history that was never recorded.

**Checks are data.** A check is `select` / `predicate` / `aggregate` JSON,
validated on save. There is no `eval()` anywhere near it and `verify_tree.py`
enforces that. This is what makes a connector pack shippable as content
reviewed by a compliance specialist rather than a patch reviewed by an engineer.

**Weak identifiers never establish identity.** An IP plus a hostname agreeing is
a guess, not a match — both get reassigned. Only vendor-issued authoritative
identifiers auto-merge; everything else becomes a reviewable proposal, and the
duplicate record is never deleted, so a wrong merge is recoverable.

**Inconclusive is not Pass.** A check that found no observations returns
Inconclusive and is excluded from the score, reported instead as reduced
coverage. A customer with no connectors scores 0% coverage, never 100%
compliance. A failing Critical check sets a hard-gate flag, because an average
that hides an open management port on the internet is worse than no number.

**Automation proposes, humans dispose.** The GRC bridge creates evidence and
raises findings. It never marks a control compliant and never closes a finding —
a recovered check is annotated "ready for verification" and left for a reviewer.

**System Manager is not a tenancy bypass.** Administering the platform is not
authorisation to read a customer's firewall topology. Cross-tenant reads require
the explicit `Infra Cross Tenant` role and every use writes an access log.

## Verifying a build

```bash
python3 verify_tree.py      # structural guard — no site, no DB, no network
python3 tests/test_offline.py
bench --site your.site run-tests --app alphax_infra   # integration
```

`verify_tree.py` catches the defect classes that install cleanly on a developer
bench and fail on a real site: hook targets that no longer resolve, doctype
`field_order` drift, link targets that do not exist, a client-scoped doctype
missing from `permission_query_conditions`, and check definitions that would
fail at run time.

Since v0.1.1 it also enforces the contracts that broke on first install:
controller class names must match Frappe's derivation
(`doctype.replace(" ", "").replace("-", "")` — this is why `AlphaX` cannot be
title-cased from its slug); no fieldname may collide with a MariaDB reserved
word; raw SQL must quote every dotted reserved identifier; a unique index may
not collide on a blank value; and nothing may write to a GRC field outside
`FIELD_MAP`, because Frappe silently ignores an assignment to a field that does
not exist. Run it before every push.

## What this release does not do

Stated plainly, because the gap between a specification and a shipped v0.1.0 is
where trust is lost:

- **No collector.** The ingest API, enrolment, signed-batch verification and
  replay protection are complete and tested, but the collector binary that
  talks to it is a separate artifact on its own release train. Anything
  on-premises — Active Directory, network devices, hypervisors, agent-based
  endpoint data — is not collected in this release.
- **No reports.** Check results, readiness scoring and control coverage are all
  queryable via the API; the executive and technical report templates are not
  built yet.
- **No assessor cockpit.** The desk workspace, list views and forms are the
  interface for now.
- **32 checks.** Identity-heavy, because that is where the findings are. Not a
  complete ISO 27001 or NCA ECC assessment, and the app does not claim to be one.
- **Mappings are proposals.** A control mapping proposes evidence reuse; it does
  not prove the target control. Scope and sampling remain the assessor's call.

## Licence

MIT. Control references are identifiers only — no standard text is reproduced,
and `verify_tree.py` checks for it.

© 2026 Neotec Integrated Solutions.
