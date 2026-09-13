#!/usr/bin/env python3
# Copyright (c) 2026, Neotec Integrated Solutions
"""
Structural integrity guard for alphax_infra.

Runs without Frappe, without a site and without a database, so it can gate a
commit or a CI job before anything is deployed. It exists because the recurring
defect classes in this codebase's history are structural rather than logical:
a hook pointing at a module that was moved, a doctype whose field_order drifted
from its fields, a deleted build file, a version string that disagrees with
itself. Each of those installs cleanly on a developer bench and fails on Frappe
Cloud, which is the worst possible place to find out.

Usage:
    python3 verify_tree.py            # all checks
    python3 verify_tree.py --quiet    # failures only
    exit code 0 = clean, 1 = defects found
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(ROOT, "alphax_infra")
DOCTYPE_DIR = os.path.join(APP, "alphax_infra", "doctype")

FAILURES: list[str] = []
PASSES: list[str] = []


def ok(msg: str) -> None:
    PASSES.append(msg)


def fail(msg: str) -> None:
    FAILURES.append(msg)


def check(label: str):
    def deco(fn):
        def wrapper():
            before = len(FAILURES)
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                fail(f"{label}: check itself raised {type(exc).__name__}: {exc}")
            if len(FAILURES) == before:
                ok(label)

        wrapper.__name__ = fn.__name__
        return wrapper

    return deco


# ---------------------------------------------------------------------------
# 1. Build files
# ---------------------------------------------------------------------------


@check("build files present")
def check_build_files():
    for rel in ("pyproject.toml", "setup.py", "MANIFEST.in", "README.md"):
        if not os.path.exists(os.path.join(ROOT, rel)):
            fail(f"build file missing: {rel} — Frappe Cloud wheel builds will fail")


@check("version strings agree")
def check_version_agreement():
    init = os.path.join(APP, "__init__.py")
    hooks = os.path.join(APP, "hooks.py")

    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', open(init).read())
    if not m:
        fail("__init__.py has no __version__")
        return
    version = m.group(1)

    h = re.search(r'app_version\s*=\s*["\']([^"\']+)["\']', open(hooks).read())
    if h and h.group(1) != version:
        fail(f"hooks.app_version={h.group(1)} disagrees with __init__.__version__={version}")

    changelog = os.path.join(ROOT, f"CHANGELOG_v{version}.md")
    if not os.path.exists(changelog):
        fail(f"no CHANGELOG_v{version}.md for the declared version")


# ---------------------------------------------------------------------------
# 2. Python
# ---------------------------------------------------------------------------


def _py_files() -> list[str]:
    out = []
    for base, dirs, files in os.walk(APP):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        out.extend(os.path.join(base, f) for f in files if f.endswith(".py"))
    return out


@check("all Python parses")
def check_python_parses():
    for path in _py_files():
        try:
            ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError as exc:
            fail(f"syntax error in {os.path.relpath(path, ROOT)}:{exc.lineno}: {exc.msg}")


@check("every package has __init__.py")
def check_package_inits():
    for base, dirs, files in os.walk(APP):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        if any(f.endswith(".py") for f in files) and "__init__.py" not in files:
            fail(f"package without __init__.py: {os.path.relpath(base, ROOT)}")


@check("no eval/exec in rule handling")
def check_no_dynamic_execution():
    """
    The check engine takes customer-influenced JSON. eval() anywhere near it
    turns a content pack into remote code execution.
    """
    for path in _py_files():
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec", "compile"):
                    fail(
                        f"{node.func.id}() at {os.path.relpath(path, ROOT)}:{node.lineno} — "
                        f"not permitted; predicates are walked explicitly"
                    )


@check("no hardcoded secrets")
def check_no_secrets():
    pattern = re.compile(
        r'(client_secret|password|api_key|private_key)\s*=\s*["\'][A-Za-z0-9+/_\-]{12,}["\']',
        re.IGNORECASE,
    )
    for path in _py_files():
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            if pattern.search(line) and "get_password" not in line:
                fail(f"possible hardcoded secret at {os.path.relpath(path, ROOT)}:{i}")


# ---------------------------------------------------------------------------
# 3. Hooks
# ---------------------------------------------------------------------------


def _load_hooks() -> dict:
    spec = importlib.util.spec_from_file_location("_infra_hooks", os.path.join(APP, "hooks.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {k: v for k, v in vars(mod).items() if not k.startswith("__")}


def _dotted_path_resolves(dotted: str) -> bool:
    """
    Resolve `alphax_infra.x.y.func` against the source tree.

    This is the check that catches package-level misplacement: a function that
    exists but sits in a module the hook does not point at. It is the defect
    class that has cost the most time historically, and it is invisible until
    a scheduler tick or a migration tries to import the target.
    """
    parts = dotted.split(".")
    if parts[0] != "alphax_infra":
        return True  # foreign app target, not ours to verify

    for split in range(len(parts), 1, -1):
        module_rel = os.path.join(*parts[1:split])
        for candidate in (
            os.path.join(APP, module_rel + ".py"),
            os.path.join(APP, module_rel, "__init__.py"),
        ):
            if not os.path.exists(candidate):
                continue
            attrs = parts[split:]
            if not attrs:
                return True
            tree = ast.parse(open(candidate, encoding="utf-8").read())
            names = {
                n.name
                for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            }
            for n in tree.body:
                if isinstance(n, ast.Assign):
                    names.update(t.id for t in n.targets if isinstance(t, ast.Name))
            return attrs[0] in names
    return False


@check("hook targets are importable")
def check_hook_targets():
    hooks = _load_hooks()
    targets: list[tuple[str, str]] = []

    for key in ("before_install", "after_install", "after_migrate", "before_migrate"):
        if hooks.get(key):
            targets.append((key, hooks[key]))

    for when, methods in (hooks.get("scheduler_events") or {}).items():
        for m in methods:
            targets.append((f"scheduler_events.{when}", m))

    for dt, events in (hooks.get("doc_events") or {}).items():
        for event, handlers in events.items():
            for h in handlers if isinstance(handlers, list) else [handlers]:
                targets.append((f"doc_events.{dt}.{event}", h))

    for dt, handler in (hooks.get("permission_query_conditions") or {}).items():
        targets.append((f"permission_query_conditions.{dt}", handler))
    for dt, handler in (hooks.get("has_permission") or {}).items():
        targets.append((f"has_permission.{dt}", handler))

    for origin, dotted in targets:
        if not _dotted_path_resolves(dotted):
            fail(f"hook target does not resolve: {origin} -> {dotted}")


@check("required_apps declares alphax_grc")
def check_required_apps():
    hooks = _load_hooks()
    if "alphax_grc" not in (hooks.get("required_apps") or []):
        fail(
            "required_apps must contain alphax_grc — this app links to GRC doctypes "
            "and will fail at migrate without it"
        )


@check("fixtures stay empty")
def check_fixtures_empty():
    hooks = _load_hooks()
    if hooks.get("fixtures"):
        fail(
            "fixtures is non-empty — fixtures overwrite on every migrate and would "
            "reset client-tuned checks; seed through install.py instead"
        )


# ---------------------------------------------------------------------------
# 4. DocTypes
# ---------------------------------------------------------------------------


def _doctype_jsons() -> list[tuple[str, dict]]:
    out = []
    if not os.path.isdir(DOCTYPE_DIR):
        return out
    for slug in sorted(os.listdir(DOCTYPE_DIR)):
        d = os.path.join(DOCTYPE_DIR, slug)
        if not os.path.isdir(d):
            continue
        p = os.path.join(d, f"{slug}.json")
        if os.path.exists(p):
            out.append((slug, json.load(open(p, encoding="utf-8"))))
    return out


@check("doctype json is well formed")
def check_doctype_json():
    for slug, doc in _doctype_jsons():
        if doc.get("module") != "AlphaX Infra":
            fail(f"{slug}: module is {doc.get('module')!r}, expected 'AlphaX Infra'")

        order = doc.get("field_order") or []
        fields = [f.get("fieldname") for f in doc.get("fields") or []]
        if set(order) != set(fields):
            missing = set(fields) - set(order)
            extra = set(order) - set(fields)
            fail(f"{slug}: field_order drift — missing {sorted(missing)}, stale {sorted(extra)}")

        if len(fields) != len(set(fields)):
            fail(f"{slug}: duplicate fieldnames")

        if not doc.get("istable") and not doc.get("permissions"):
            fail(f"{slug}: no permissions block — the doctype would be inaccessible")


@check("doctype controllers exist")
def check_doctype_controllers():
    for slug, _doc in _doctype_jsons():
        d = os.path.join(DOCTYPE_DIR, slug)
        for required in ("__init__.py", f"{slug}.py"):
            if not os.path.exists(os.path.join(d, required)):
                fail(f"{slug}: missing {required}")


@check("link targets exist")
def check_link_targets():
    """
    Every Link option must be a doctype we ship or one from a known foreign app.
    A typo here installs fine and fails on first use.
    """
    ours = {doc.get("name") for _slug, doc in _doctype_jsons()}
    foreign = {
        "User", "Role", "File", "GRC Client Profile", "GRC Asset Inventory",
        "GRC Evidence", "GRC Audit Finding", "GRC Control", "GRC Framework",
    }
    known = ours | foreign

    for slug, doc in _doctype_jsons():
        for f in doc.get("fields") or []:
            if f.get("fieldtype") in ("Link", "Table", "Table MultiSelect"):
                target = f.get("options")
                if target and target not in known:
                    fail(f"{slug}.{f['fieldname']}: link target {target!r} is not defined anywhere")


@check("client scoping is complete")
def check_client_scoping():
    """
    Every doctype carrying a `client` field must be listed in
    permission_query_conditions, or its list view leaks across tenants while
    the API does not — the worst kind of inconsistency to debug.
    """
    hooks = _load_hooks()
    scoped = set(hooks.get("permission_query_conditions") or {})

    for slug, doc in _doctype_jsons():
        if doc.get("istable") or doc.get("issingle"):
            continue
        has_client = any(f.get("fieldname") == "client" for f in doc.get("fields") or [])
        if has_client and doc["name"] not in scoped:
            fail(
                f"{doc['name']} has a client field but no permission_query_conditions entry "
                f"— list views and exports would not be tenant-filtered"
            )


# ---------------------------------------------------------------------------
# 5. Content
# ---------------------------------------------------------------------------


@check("check catalogue is valid")
def check_catalog():
    path = os.path.join(APP, "data", "check_catalog.json")
    if not os.path.exists(path):
        fail("check_catalog.json is missing — install would seed nothing")
        return

    catalog = json.load(open(path, encoding="utf-8"))
    checks = catalog.get("checks") or []
    if not checks:
        fail("check catalogue is empty")
        return

    sys.path.insert(0, ROOT)
    try:
        from alphax_infra.core.rules import validate_definition
    except ImportError as exc:
        fail(f"cannot import the rule engine to validate the catalogue: {exc}")
        return

    codes = set()
    for entry in checks:
        code = entry.get("check_code")
        if not code:
            fail("catalogue entry with no check_code")
            continue
        if code in codes:
            fail(f"duplicate check_code in catalogue: {code}")
        codes.add(code)

        for required in ("check_name", "definition", "description", "remediation"):
            if not entry.get(required):
                fail(f"{code}: missing {required}")

        problems = validate_definition(entry.get("definition") or {})
        for p in problems:
            fail(f"{code}: {p}")

        if entry.get("severity") not in ("Critical", "High", "Medium", "Low", "Informational"):
            fail(f"{code}: severity {entry.get('severity')!r} is not a valid option")


@check("no standard text is reproduced")
def check_no_standard_text():
    """
    Standards are copyrighted. The catalogue stores control identifiers and our
    own wording, never clause text. A long quoted passage in a description is
    the shape that gets an app pulled from a marketplace.
    """
    path = os.path.join(APP, "data", "check_catalog.json")
    if not os.path.exists(path):
        return
    catalog = json.load(open(path, encoding="utf-8"))
    for entry in catalog.get("checks") or []:
        for field in ("description", "remediation"):
            text = entry.get(field) or ""
            if re.search(r'"[^"]{120,}"', text):
                fail(
                    f"{entry.get('check_code')}: {field} contains a long quoted passage — "
                    f"verify it is not standard text"
                )


@check("workspace links resolve")
def check_workspace():
    path = os.path.join(APP, "alphax_infra", "workspace", "alphax_infra", "alphax_infra.json")
    if not os.path.exists(path):
        fail("workspace json is missing")
        return
    ws = json.load(open(path, encoding="utf-8"))
    ours = {doc.get("name") for _slug, doc in _doctype_jsons()}

    for link in ws.get("links") or []:
        if link.get("type") == "Link" and link.get("link_type") == "DocType":
            if link.get("link_to") not in ours:
                fail(f"workspace links to unknown doctype: {link.get('link_to')}")

    for sc in ws.get("shortcuts") or []:
        if sc.get("type") == "DocType" and sc.get("link_to") not in ours:
            fail(f"workspace shortcut targets unknown doctype: {sc.get('link_to')}")

    try:
        json.loads(ws.get("content") or "[]")
    except (TypeError, ValueError) as exc:
        fail(f"workspace content is not valid JSON: {exc}")


@check("patches are registered and exist")
def check_patches():
    path = os.path.join(APP, "patches.txt")
    if not os.path.exists(path):
        fail("patches.txt is missing")
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue
        rel = os.path.join(APP, *line.split(".")[1:]) + ".py"
        if not os.path.exists(rel):
            fail(f"patch registered but not present: {line}")
            continue
        tree = ast.parse(open(rel, encoding="utf-8").read())
        if not any(
            isinstance(n, ast.FunctionDef) and n.name == "execute" for n in tree.body
        ):
            fail(f"patch {line} has no execute()")


# ---------------------------------------------------------------------------
# 6. Runtime contracts
#
# Every check in this section exists because the corresponding defect shipped
# in v0.1.0 and was only found when the app was opened on a live site.
# ---------------------------------------------------------------------------


@check("controller class names match Frappe's derivation")
def check_controller_class_names():
    """
    Frappe resolves a controller class as `doctype.replace(" ", "").replace("-", "")`
    and raises a bare `ImportError: <doctype>` when it is absent — a message
    that names the doctype and says nothing about the cause.

    This caught `AlphaxInfraSettings` where Frappe wanted `AlphaXInfraSettings`:
    a generator that title-cased the folder slug cannot recover the interior
    capital in "AlphaX". The doctype installed fine and failed the moment
    anyone opened the form.
    """
    for slug, doc in _doctype_jsons():
        expected = doc["name"].replace(" ", "").replace("-", "")
        path = os.path.join(DOCTYPE_DIR, slug, f"{slug}.py")
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding="utf-8").read())
        classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
        if expected not in classes:
            fail(
                f"{doc['name']}: controller must define class {expected!r} "
                f"(found {sorted(classes) or 'none'}) — Frappe raises a bare "
                f"ImportError otherwise"
            )


# MariaDB reserved words. A fieldname here is legal in a Frappe doctype and
# becomes a syntax error the first time raw SQL references it unquoted.
SQL_RESERVED = {
    "add", "all", "alter", "analyze", "and", "as", "asc", "between", "bigint",
    "binary", "blob", "both", "by", "call", "cascade", "case", "change", "char",
    "character", "check", "collate", "column", "condition", "constraint",
    "continue", "convert", "create", "cross", "default", "delete", "desc",
    "describe", "distinct", "div", "double", "drop", "else", "exists",
    "explain", "false", "fetch", "float", "for", "force", "foreign", "from",
    "group", "having", "if", "ignore", "in", "index", "inner", "insert", "int",
    "integer", "interval", "into", "is", "join", "key", "keys", "kill",
    "leading", "leave", "left", "like", "limit", "lines", "load", "lock",
    "long", "match", "not", "null", "on", "optimize", "option", "or", "order",
    "out", "outer", "over", "partition", "primary", "procedure", "purge",
    "range", "read", "references", "rename", "replace", "require", "restrict",
    "return", "revoke", "right", "rows", "schema", "select", "set", "show",
    "signal", "sql", "table", "then", "to", "true", "union", "unique", "unlock",
    "update", "usage", "use", "using", "values", "varchar", "when", "where",
    "while", "window", "with", "write", "xor",
}


@check("no fieldname collides with a SQL reserved word")
def check_reserved_fieldnames():
    """
    Frappe accepts `check` as a fieldname and quotes it in its own DDL, so the
    column is created and everything looks fine — until any hand-written query
    says `r.check` and MariaDB rejects it as a syntax error. That was a live
    defect in `Infra Check Result`.
    """
    for slug, doc in _doctype_jsons():
        for f in doc.get("fields") or []:
            fn = (f.get("fieldname") or "").lower()
            if fn in SQL_RESERVED:
                fail(
                    f"{doc['name']}.{f['fieldname']}: collides with the SQL reserved "
                    f"word {fn!r} — rename it; raw queries will not parse"
                )


@check("raw SQL quotes every identifier it dots into")
def check_sql_identifier_quoting():
    """
    Scoped to SQL string literals only. Scanning every Python line for `x.key`
    matches ordinary attribute access and buries the real hits.
    """
    sql_block = re.compile(r'"""(.*?)"""', re.S)
    for path in _py_files():
        src = open(path, encoding="utf-8").read()
        for m in sql_block.finditer(src):
            block = m.group(1)
            if not re.search(r"\b(SELECT|UPDATE|DELETE|INSERT|FROM|JOIN)\b", block):
                continue
            line_no = src[: m.start()].count("\n") + 1
            for ident in re.finditer(r"\b[a-z]\.([a-z_]+)\b", block):
                word = ident.group(1)
                if word in SQL_RESERVED and f"`{word}`" not in block:
                    fail(
                        f"{os.path.relpath(path, ROOT)}:~{line_no}: unquoted reserved "
                        f"word {word!r} in a dotted SQL identifier"
                    )


@check("unique indexes cannot collide on a blank value")
def check_unique_optional_fields():
    """
    Frappe writes an unset Data field as '' rather than NULL, so `unique: 1` on
    an optional field with no default rejects the *second* row created before
    anyone fills it in. `Infra Collector.fingerprint` hit exactly this: a
    second collector could not be created until the first had enrolled.
    """
    for slug, doc in _doctype_jsons():
        for f in doc.get("fields") or []:
            if not f.get("unique"):
                continue
            if f.get("reqd") or f.get("default"):
                continue
            autoname = doc.get("autoname") or ""
            if autoname == f"field:{f['fieldname']}":
                continue  # the naming field is always populated
            fail(
                f"{doc['name']}.{f['fieldname']}: unique but neither mandatory nor "
                f"defaulted — blank values collide on the index"
            )


@check("mandatory fields are writable on every path that creates them")
def check_audit_rows_are_insertable():
    """
    `Infra Discovery Batch` is written from the guest ingest endpoint to record
    a rejection. When a batch arrives from an unknown collector there is no
    client to resolve, so a mandatory `client` made the audit insert fail and
    the refusal went unrecorded — the one thing that row exists to prevent.
    """
    for slug, doc in _doctype_jsons():
        if doc["name"] != "Infra Discovery Batch":
            continue
        for f in doc.get("fields") or []:
            if f.get("fieldname") == "client" and f.get("reqd"):
                fail(
                    "Infra Discovery Batch.client is mandatory — a rejected batch "
                    "from an unidentified collector could not be logged"
                )


@check("no writes to fields that do not exist in the GRC schema")
def check_grc_field_map():
    """
    Setting an unknown attribute on a Frappe Document raises nothing and
    persists nothing. `doc.description = body` against a doctype with no
    `description` field produced evidence records that looked correct and were
    empty. All GRC field names now go through one map, and this asserts that
    nothing bypasses it.
    """
    path = os.path.join(APP, "core", "grc_bridge.py")
    if not os.path.exists(path):
        fail("grc_bridge.py is missing")
        return
    src = open(path, encoding="utf-8").read()

    if "FIELD_MAP" not in src:
        fail("grc_bridge.py has no FIELD_MAP — GRC field names must be declared in one place")

    # Direct attribute assignment onto a GRC document, outside the map.
    for i, line in enumerate(src.split("\n"), 1):
        m = re.match(r"\s*doc\.([a-z_]+)\s*=\s*", line)
        if m and m.group(1) not in ("client", "related_doctype", "related_document",
                                    "asset_type", "notes", "flags"):
            fail(
                f"grc_bridge.py:{i}: direct assignment to doc.{m.group(1)} — route it "
                f"through _set()/FIELD_MAP so a missing field is detected, not ignored"
            )


@check("frappe.utils is imported, not attribute-accessed")
def check_frappe_utils_imports():
    """
    `frappe.utils.add_days` works only if something else already imported the
    submodule. It is a latent AttributeError that depends on import order
    elsewhere in the process.
    """
    for path in _py_files():
        src = open(path, encoding="utf-8").read()
        for i, line in enumerate(src.split("\n"), 1):
            if re.search(r"\bfrappe\.utils\.[a-z_]+\(", line):
                fail(
                    f"{os.path.relpath(path, ROOT)}:{i}: use an explicit "
                    f"`from frappe.utils import ...` rather than frappe.utils.x()"
                )


@check("Single doctypes are not probed with frappe.db.exists")
def check_single_existence_probe():
    """
    A Single has no row keyed by its name; its values live in `tabSingles`.
    `frappe.db.exists("X Settings", "X Settings")` does not mean what it looks
    like it means, and getting it wrong left the settings defaults unwritten —
    which read back as falsy and disabled the whole module.
    """
    singles = {doc["name"] for _slug, doc in _doctype_jsons() if doc.get("issingle")}
    for path in _py_files():
        src = open(path, encoding="utf-8").read()
        for i, line in enumerate(src.split("\n"), 1):
            for name in singles:
                if f'frappe.db.exists("{name}"' in line:
                    fail(
                        f"{os.path.relpath(path, ROOT)}:{i}: frappe.db.exists on the "
                        f"Single {name!r} — query tabSingles instead"
                    )


@check("roles referenced by permissions are created before doctype sync")
def check_role_creation_ordering():
    """
    DocType sync runs between before_install and after_install. Every doctype
    JSON here carries permission rows naming app roles, so those roles have to
    exist before the sync, not after it.
    """
    src = open(os.path.join(APP, "install.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "before_install":
            body = ast.dump(node)
            if "_create_roles" not in body:
                fail("install.before_install does not create roles — doctype sync runs first")
            return
    fail("install.py has no before_install")



# ---------------------------------------------------------------------------


CHECKS = [
    check_build_files,
    check_version_agreement,
    check_python_parses,
    check_package_inits,
    check_no_dynamic_execution,
    check_no_secrets,
    check_hook_targets,
    check_required_apps,
    check_fixtures_empty,
    check_doctype_json,
    check_doctype_controllers,
    check_link_targets,
    check_client_scoping,
    check_catalog,
    check_no_standard_text,
    check_workspace,
    check_patches,
    check_controller_class_names,
    check_reserved_fieldnames,
    check_sql_identifier_quoting,
    check_unique_optional_fields,
    check_audit_rows_are_insertable,
    check_grc_field_map,
    check_frappe_utils_imports,
    check_single_existence_probe,
    check_role_creation_ordering,
]


def main() -> int:
    quiet = "--quiet" in sys.argv
    for fn in CHECKS:
        fn()

    if not quiet:
        for line in PASSES:
            print(f"  PASS  {line}")

    if FAILURES:
        print()
        for line in FAILURES:
            print(f"  FAIL  {line}")
        print(f"\n{len(FAILURES)} defect(s), {len(PASSES)} group(s) clean")
        return 1

    print(f"\nverify_tree: {len(PASSES)} check group(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
