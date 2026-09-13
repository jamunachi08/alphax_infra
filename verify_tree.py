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
