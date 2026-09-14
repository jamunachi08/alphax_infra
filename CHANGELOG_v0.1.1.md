# AlphaX Infra — v0.1.1

Corrective release. Every item below is a defect found after v0.1.0 was
installed on a live site, plus the guard check that now prevents each class
from recurring.

## Fixed — blocking

**Settings form raised `ImportError: AlphaX Infra Settings`.**
Frappe resolves a controller class as `doctype.replace(" ", "").replace("-", "")`,
so it wanted `AlphaXInfraSettings`. The generator title-cased the folder slug
and produced `AlphaxInfraSettings`, which cannot recover the interior capital
in "AlphaX". The doctype installed cleanly and failed the moment the form was
opened. All fifteen controllers were audited; this was the only one affected.

**`Infra Check Result.check` collided with a MariaDB reserved word.**
Frappe quotes its own DDL, so the column was created without complaint. Every
hand-written query referencing `r.check` — check evaluation, readiness scoring,
control coverage and the critical-failure alert — would have been a syntax
error on first run. Renamed to `infra_check`, with a patch that carries over
any rows a v0.1.0 site had written and drops the orphan column.

**The GRC bridge wrote to fields that do not exist in alphax_grc v2.14.0.**
Verified against the live schema rather than assumed:

| Wrote | Actual field |
|---|---|
| `GRC Evidence.description` | `notes` — no `description` exists |
| `GRC Evidence.collection_date` | `collected_on` |
| `GRC Evidence.control` / `.framework` | neither exists; now linked via `related_doctype` / `related_document` |
| `GRC Audit Finding.description` | `observation` |
| `GRC Audit Finding.control` | `control_reference` |

Setting an unknown attribute on a Frappe Document raises nothing and persists
nothing, so this would have produced evidence and findings that looked correct
and were empty. All GRC field names now resolve through a single `FIELD_MAP`.

**`GRC Audit Finding.framework` is a Select with a fixed option list.**
The catalogue stores `ISO/IEC 27001:2022`, which is not one of its options, so
every finding insert would have failed validation partway through a run.
`FRAMEWORK_MAP` translates to the short labels GRC actually accepts.

**`GRC Asset Inventory.asset_type` options do not match ours.** `Endpoint`,
`Identity` and `Cloud Resource` are not in its list and there is no `Other`, so
the fallback resolved to a blank first option. Replaced with an explicit map.

**Finding bodies are Text Editor fields** and were being written as plain text
with newlines, collapsing into one unreadable paragraph in the place an auditor
reads it. Now emitted as HTML.

## Fixed — latent

- **`Infra Collector.fingerprint` was unique but optional.** Frappe writes an
  unset Data field as `''`, not NULL, so a second collector could not be created
  until the first had enrolled. Uniqueness moved into the controller, where
  "set and already taken" is distinguishable from "not enrolled yet".
- **Firm-wide checks were invisible to scoped users.** `Infra Check` has an
  optional client, and the standard scope query excludes blank values — which
  would have hidden all 32 shipped catalogue checks from every assessor. It now
  uses a variant that treats a blank client as firm-wide.
- **Rejected batches could fail to log.** `client` was mandatory on
  `Infra Discovery Batch`, but a batch from an unknown collector has no
  resolvable client; and a repeated rejection collided on the unique
  `content_hash` index. Both defeated the row's only purpose. `client` is now
  optional, rejections carry a random hash, and the real digest goes in the
  reason.
- **Roles were created after doctype sync.** Every doctype JSON carries
  permission rows naming the app's roles, and sync runs between
  `before_install` and `after_install`. Role creation moved to `before_install`.
- **Settings defaults were never materialised.** `_seed_settings` probed a
  Single with `frappe.db.exists`, which does not mean what it appears to for a
  Single. Until the defaults were written, `settings.enabled` read back falsy
  and the module behaved as though switched off. Now queries `tabSingles`.
- **`frappe.utils.add_days` / `get_url` were attribute-accessed** without
  importing the submodule — a latent `AttributeError` dependent on import order
  elsewhere in the process. Now explicit imports.

## Added — guard checks

`verify_tree.py` grows from 17 to 26 groups, one per defect class above:
controller class names match Frappe's derivation; no fieldname collides with a
MariaDB reserved word; raw SQL quotes every dotted reserved identifier; no
unique index can collide on a blank value; audit rows stay insertable; no
direct attribute writes to GRC documents outside `FIELD_MAP`; `frappe.utils` is
imported rather than attribute-accessed; Singles are not probed with
`frappe.db.exists`; roles are created before doctype sync.

The reserved-word list is MariaDB's *reserved* set only. Non-reserved keywords
like `status` and `row` are legal unquoted identifiers, and flagging them would
have produced noise that trains you to ignore the guard.

## Upgrade

```bash
bench --site <site> migrate
```

The patch is idempotent and inspects the live schema rather than assuming which
columns exist. Check results written under v0.1.0 are carried over; there should
be none, since the queries that wrote them could not have run.
