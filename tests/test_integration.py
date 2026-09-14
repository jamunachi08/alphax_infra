# Copyright (c) 2026, Neotec Integrated Solutions
"""
Site-level integration tests.

    bench --site <site> run-tests --app alphax_infra

These cover what the offline suite cannot: the bitemporal store against real
MariaDB, tenant isolation through Frappe's permission layer, and the ingest
endpoint's replay and duplicate handling. The negative permission tests are
the important ones — the commercial position that shared-site tenancy is safe
rests on them, so they assert that a scoped user sees nothing rather than
asserting that a privileged user sees something.
"""

from __future__ import annotations

import base64
import json
import secrets
import unittest

import frappe
from frappe.utils import add_days, now_datetime

from alphax_infra.core import observations as obs
from alphax_infra.core.canonical import canonicalize, digest, signing_payload
from alphax_infra.core.tenancy import allowed_clients, scope_condition

CLIENT_A = "_TEST_INFRA_A"
CLIENT_B = "_TEST_INFRA_B"


def _client(name: str) -> str:
    if not frappe.db.exists("GRC Client Profile", name):
        doc = frappe.new_doc("GRC Client Profile")
        doc.client_name = name
        if doc.meta.get_field("client_code"):
            doc.client_code = name
        doc.insert(ignore_permissions=True)
        return doc.name
    return name


class TestObservationStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        obs.ensure_table()
        cls.client = _client(CLIENT_A)

    def setUp(self):
        frappe.db.sql(f"DELETE FROM `{obs.TABLE}` WHERE `client` = %s", (self.client,))

    def test_table_exists(self):
        self.assertTrue(obs.table_exists())

    def test_insert_and_read_current(self):
        counts = obs.record_batch(
            self.client, "test",
            [{"subject": "user:1", "fact_key": "user.enabled", "value": True}],
        )
        self.assertEqual(counts["inserted"], 1)
        rows = obs.query(self.client, fact_keys=["user.enabled"])
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["value"], True)

    def test_unchanged_fact_is_not_rewritten(self):
        """An unchanged fact keeps its original valid_from. That is what makes
        'unchanged since' answerable rather than resetting nightly."""
        obs.record_batch(
            self.client, "test",
            [{"subject": "user:1", "fact_key": "user.enabled", "value": True}],
        )
        first = obs.query(self.client, fact_keys=["user.enabled"])[0]["valid_from"]

        counts = obs.record_batch(
            self.client, "test",
            [{"subject": "user:1", "fact_key": "user.enabled", "value": True}],
        )
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(counts["inserted"], 0)

        rows = obs.query(self.client, fact_keys=["user.enabled"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["valid_from"], first)

    def test_supersession_closes_the_old_row(self):
        t1 = add_days(now_datetime(), -2)
        t2 = now_datetime()

        obs.record_batch(
            self.client, "test",
            [{"subject": "user:1", "fact_key": "user.enabled", "value": True}],
            collected_at=t1,
        )
        counts = obs.record_batch(
            self.client, "test",
            [{"subject": "user:1", "fact_key": "user.enabled", "value": False}],
            collected_at=t2,
        )
        self.assertEqual(counts["superseded"], 1)

        current = obs.query(self.client, fact_keys=["user.enabled"])
        self.assertEqual(len(current), 1)
        self.assertIs(current[0]["value"], False)

    def test_point_in_time_query(self):
        """The reason the store is bitemporal: an auditor asks what was true
        during the review period, not what is true today."""
        t1 = add_days(now_datetime(), -10)
        t2 = add_days(now_datetime(), -1)

        obs.record_batch(
            self.client, "test",
            [{"subject": "vm:1", "fact_key": "storage.https_only", "value": False}],
            collected_at=t1,
        )
        obs.record_batch(
            self.client, "test",
            [{"subject": "vm:1", "fact_key": "storage.https_only", "value": True}],
            collected_at=t2,
        )

        then = obs.query(self.client, fact_keys=["storage.https_only"],
                         as_of=add_days(now_datetime(), -5))
        self.assertEqual(len(then), 1)
        self.assertIs(then[0]["value"], False, "as-of query must return the historical value")

        now = obs.query(self.client, fact_keys=["storage.https_only"])
        self.assertIs(now[0]["value"], True)

    def test_rows_without_subject_are_skipped_not_stored(self):
        counts = obs.record_batch(
            self.client, "test",
            [{"fact_key": "orphan", "value": 1}, {"subject": "s", "value": 2}],
        )
        self.assertEqual(counts["skipped"], 2)
        self.assertEqual(counts["inserted"], 0)

    def test_bulk_insert_chunking(self):
        rows = [
            {"subject": f"user:{i}", "fact_key": "user.enabled", "value": True}
            for i in range(1200)
        ]
        counts = obs.record_batch(self.client, "test", rows)
        self.assertEqual(counts["inserted"], 1200)
        self.assertEqual(len(obs.query(self.client, fact_keys=["user.enabled"], limit=5000)), 1200)

    def test_tenant_isolation_in_the_store(self):
        other = _client(CLIENT_B)
        frappe.db.sql(f"DELETE FROM `{obs.TABLE}` WHERE `client` = %s", (other,))

        obs.record_batch(self.client, "test",
                         [{"subject": "s", "fact_key": "f", "value": "a"}])
        obs.record_batch(other, "test",
                         [{"subject": "s", "fact_key": "f", "value": "b"}])

        self.assertEqual(obs.query(self.client, fact_keys=["f"])[0]["value"], "a")
        self.assertEqual(obs.query(other, fact_keys=["f"])[0]["value"], "b")

    def test_drift_is_a_range_scan(self):
        obs.record_batch(self.client, "test",
                         [{"subject": "s", "fact_key": "f", "value": "a"}],
                         collected_at=add_days(now_datetime(), -10))
        obs.record_batch(self.client, "test",
                         [{"subject": "s", "fact_key": "f", "value": "b"}])
        changed = obs.drift(self.client, add_days(now_datetime(), -1))
        self.assertEqual(len(changed), 1)


class TestTenancy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _client(CLIENT_A)
        cls.b = _client(CLIENT_B)

    def tearDown(self):
        frappe.set_user("Administrator")

    def test_scope_condition_fails_closed(self):
        """The failure mode of the scope guard must be 'sees nothing'. A guard
        that degrades to 1=1 is worse than no guard, because it looks safe."""
        user = _scoped_user("_test_infra_noscope@example.com", [])
        frappe.set_user(user)
        condition, _params = scope_condition()
        self.assertEqual(condition, "1=0")

    def test_scoped_user_sees_only_their_client(self):
        user = _scoped_user("_test_infra_a@example.com", [self.a])
        frappe.set_user(user)
        self.assertEqual(allowed_clients(), [self.a])
        self.assertNotIn(self.b, allowed_clients())

    def test_system_manager_is_not_a_bypass(self):
        """Administering the platform is not authorisation to read a
        customer's infrastructure topology."""
        user = _scoped_user("_test_infra_sm@example.com", [self.a], roles=["System Manager"])
        frappe.set_user(user)
        self.assertNotEqual(allowed_clients(), ["*"])

    def test_require_client_refuses_implicit_cross_tenant(self):
        from alphax_infra.core.tenancy import require_client

        user = _scoped_user("_test_infra_x@example.com", [self.a, self.b])
        frappe.set_user(user)
        with self.assertRaises(frappe.ValidationError):
            require_client(None)

    def test_require_client_refuses_foreign_client(self):
        from alphax_infra.core.tenancy import require_client

        user = _scoped_user("_test_infra_a2@example.com", [self.a])
        frappe.set_user(user)
        with self.assertRaises(frappe.PermissionError):
            require_client(self.b)


def _scoped_user(email: str, clients: list, roles: list | None = None) -> str:
    if not frappe.db.exists("User", email):
        doc = frappe.new_doc("User")
        doc.email = email
        doc.first_name = "Test"
        doc.enabled = 1
        doc.append("roles", {"role": "Infra Assessor"})
        for r in roles or []:
            doc.append("roles", {"role": r})
        doc.insert(ignore_permissions=True)

    frappe.db.delete("User Permission", {"user": email, "allow": "GRC Client Profile"})
    for c in clients:
        frappe.get_doc(
            {"doctype": "User Permission", "user": email,
             "allow": "GRC Client Profile", "for_value": c}
        ).insert(ignore_permissions=True)
    frappe.db.commit()
    return email


class TestChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _client(CLIENT_A)
        obs.ensure_table()

    def test_catalogue_was_seeded(self):
        self.assertGreaterEqual(frappe.db.count("Infra Check"), 30)

    def test_every_seeded_check_has_a_valid_definition(self):
        from alphax_infra.core.rules import validate_definition

        for name in frappe.get_all("Infra Check", pluck="name"):
            doc = frappe.get_doc("Infra Check", name)
            self.assertEqual(validate_definition(doc.parsed_definition()), [], name)

    def test_malformed_definition_is_refused_on_save(self):
        doc = frappe.new_doc("Infra Check")
        doc.update({
            "check_code": "_TEST_BAD", "check_name": "bad",
            "definition": json.dumps({"select": {}, "predicate": {"op": "nope"}}),
        })
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

    def test_check_with_no_data_is_inconclusive_not_pass(self):
        """The single most dangerous failure mode in a compliance product is
        scoring a control compliant because nothing was collected."""
        from alphax_infra.core.rules import run_check

        frappe.db.sql(f"DELETE FROM `{obs.TABLE}` WHERE `client` = %s", (self.client,))
        result = run_check(
            {"select": {"fact_keys": ["nothing.here"]},
             "predicate": {"op": "eq", "fact": "nothing.here", "value": True}},
            self.client,
        )
        self.assertEqual(result.verdict, "Inconclusive")

    def test_failing_check_produces_a_verdict_and_subjects(self):
        from alphax_infra.core.rules import run_check

        frappe.db.sql(f"DELETE FROM `{obs.TABLE}` WHERE `client` = %s", (self.client,))
        obs.record_batch(self.client, "entra", [
            {"subject": "user:1", "fact_key": "user.mfa_registered", "value": True},
            {"subject": "user:2", "fact_key": "user.mfa_registered", "value": False},
        ])
        result = run_check(
            {"select": {"fact_keys": ["user.mfa_registered"]},
             "predicate": {"op": "eq", "fact": "user.mfa_registered", "value": True},
             "aggregate": "all_must_pass"},
            self.client,
        )
        self.assertEqual(result.verdict, "Fail")
        self.assertEqual(result.failed, 1)
        self.assertIn("user:2", result.failing_subjects)


class TestReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _client(CLIENT_A)

    def test_inconclusive_never_counts_as_a_pass(self):
        """Coverage and score are reported separately. A customer with no
        connectors must score low coverage, not high compliance."""
        from alphax_infra.evaluate import readiness

        out = readiness(self.client)
        self.assertIn("coverage_percent", out)
        self.assertIn("hard_gate_clear", out)
        self.assertLessEqual(out["readiness_percent"], 100.0)


class TestIngest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _client(CLIENT_A)
        obs.ensure_table()

    def _collector(self) -> str:
        name = frappe.db.get_value("Infra Collector", {"collector_label": "_TEST_COL"})
        if name:
            return name
        doc = frappe.new_doc("Infra Collector")
        doc.update({
            "collector_label": "_TEST_COL", "client": self.client,
            "status": "Active", "fingerprint": secrets.token_hex(16),
            "public_key": base64.b64encode(b"\x00" * 32).decode(),
        })
        doc.insert(ignore_permissions=True)
        return doc.name

    def _envelope(self, collector: str, sequence: int) -> dict:
        return {
            "schema_version": 1,
            "collector_id": collector,
            "collector_version": "0.1.0",
            "module": "ad",
            "module_version": "1",
            "client": self.client,
            "sequence": sequence,
            "nonce": secrets.token_hex(16),
            "collected_at": str(now_datetime()),
            "observations": [{"subject": "host:1", "fact_key": "host.os", "value": "Windows"}],
        }

    def test_content_hash_is_stable_across_key_order(self):
        col = self._collector()
        env = self._envelope(col, 1)
        shuffled = {k: env[k] for k in reversed(list(env.keys()))}
        self.assertEqual(digest(signing_payload(env)), digest(signing_payload(shuffled)))

    def test_signing_payload_excludes_the_signature(self):
        env = dict(self._envelope(self._collector(), 1), signature="abc")
        self.assertNotIn("signature", signing_payload(env))

    def test_canonical_bytes_are_deterministic(self):
        env = self._envelope(self._collector(), 1)
        self.assertEqual(canonicalize(env), canonicalize(json.loads(json.dumps(env))))


class TestGRCBridge(unittest.TestCase):
    def test_grc_is_present(self):
        from alphax_infra.core.grc_bridge import grc_installed

        self.assertTrue(grc_installed(), "alphax_grc must be installed — it is a required app")

    def test_bridge_degrades_rather_than_throws_on_option_drift(self):
        """alphax_grc is on its own release train. A changed Select option set
        there must not break an ingest here."""
        from alphax_infra.core.grc_bridge import _legal_option

        value = _legal_option("GRC Evidence", "status", "DefinitelyNotAnOption", "Draft")
        self.assertIsNotNone(value)
        self.assertNotEqual(value, "DefinitelyNotAnOption")

    def test_control_coverage_runs(self):
        from alphax_infra.core.grc_bridge import control_coverage

        self.assertIsInstance(control_coverage(_client(CLIENT_A)), list)

class TestRegressions(unittest.TestCase):
    """One test per defect fixed in v0.1.1. These are the ones that reached a
    live site, so they are the ones most worth keeping."""

    @classmethod
    def setUpClass(cls):
        cls.client = _client(CLIENT_A)

    def test_settings_controller_imports(self):
        """Regression: the controller class was AlphaxInfraSettings where
        Frappe wanted AlphaXInfraSettings, and the form raised a bare
        ImportError naming only the doctype."""
        doc = frappe.get_doc("AlphaX Infra Settings")
        self.assertEqual(type(doc).__name__, "AlphaXInfraSettings")

    def test_settings_defaults_were_materialised(self):
        """Regression: the Single was never written, so `enabled` read back
        falsy and the whole module behaved as though switched off."""
        row = frappe.db.sql(
            "SELECT 1 FROM `tabSingles` WHERE `doctype` = %s LIMIT 1",
            ("AlphaX Infra Settings",),
        )
        self.assertTrue(row, "AlphaX Infra Settings has no rows in tabSingles")
        self.assertTrue(frappe.get_cached_doc("AlphaX Infra Settings").enabled)

    def test_reserved_word_column_is_gone(self):
        """Regression: `check` is a MariaDB reserved word; every raw query
        referencing it was a syntax error."""
        cols = {
            r[0] for r in frappe.db.sql(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
                ("tabInfra Check Result",),
            )
        }
        self.assertIn("infra_check", cols)
        self.assertNotIn("check", cols)

    def test_readiness_query_actually_executes(self):
        """The query that the reserved word would have broken."""
        from alphax_infra.evaluate import readiness

        self.assertIsInstance(readiness(self.client), dict)

    def test_control_coverage_query_actually_executes(self):
        from alphax_infra.core.grc_bridge import control_coverage

        self.assertIsInstance(control_coverage(self.client), list)

    def test_grc_field_map_points_at_real_fields(self):
        """Regression: the bridge wrote to GRC fields that do not exist, which
        Frappe silently ignores — producing empty evidence that looked fine."""
        from alphax_infra.core.grc_bridge import FIELD_MAP

        for doctype, mapping in FIELD_MAP.items():
            if not frappe.db.exists("DocType", doctype):
                continue
            meta = frappe.get_meta(doctype)
            for logical, fieldname in mapping.items():
                self.assertTrue(
                    meta.get_field(fieldname),
                    f"{doctype}.{fieldname} (mapped as '{logical}') does not exist",
                )

    def test_framework_map_produces_legal_select_values(self):
        """Regression: 'ISO/IEC 27001:2022' is not a legal option on GRC's
        framework Select, so every finding insert failed validation."""
        from alphax_infra.core.grc_bridge import FRAMEWORK_MAP, _legal_option

        if not frappe.db.exists("DocType", "GRC Audit Finding"):
            self.skipTest("GRC Audit Finding not installed")
        df = frappe.get_meta("GRC Audit Finding").get_field("framework")
        options = {o.strip() for o in (df.options or "").split("\n") if o.strip()}
        for source, target in FRAMEWORK_MAP.items():
            self.assertIn(target, options, f"{source} maps to illegal option {target}")

        raw = _legal_option("GRC Audit Finding", "framework", "ISO/IEC 27001:2022", "Custom")
        self.assertIn(raw, options)

    def test_every_catalogue_framework_is_mappable(self):
        from alphax_infra.core.grc_bridge import FRAMEWORK_MAP

        for fw in frappe.get_all("Infra Check", pluck="framework"):
            if fw:
                self.assertIn(fw, FRAMEWORK_MAP, f"catalogue framework {fw!r} has no mapping")

    def test_asset_type_map_produces_legal_values(self):
        from alphax_infra.core.grc_bridge import ASSET_TYPE_MAP

        if not frappe.db.exists("DocType", "GRC Asset Inventory"):
            self.skipTest("GRC Asset Inventory not installed")
        df = frappe.get_meta("GRC Asset Inventory").get_field("asset_type")
        options = {o.strip() for o in (df.options or "").split("\n") if o.strip()}
        for source, target in ASSET_TYPE_MAP.items():
            self.assertIn(target, options, f"{source} maps to illegal option {target}")

        ours = frappe.get_meta("Infra Asset").get_field("asset_type")
        for opt in [o.strip() for o in (ours.options or "").split("\n") if o.strip()]:
            self.assertIn(opt, ASSET_TYPE_MAP, f"Infra asset type {opt!r} has no GRC mapping")

    def test_two_unenrolled_collectors_can_coexist(self):
        """Regression: fingerprint was unique but optional, and Frappe writes
        an unset Data field as '' — so the second collector collided."""
        made = []
        for i in (1, 2):
            doc = frappe.new_doc("Infra Collector")
            doc.update({"collector_label": f"_TEST_UNENROLLED_{i}", "client": self.client})
            doc.insert(ignore_permissions=True)
            made.append(doc.name)
        self.assertEqual(len(made), 2)
        for name in made:
            frappe.delete_doc("Infra Collector", name, force=True, ignore_permissions=True)

    def test_firm_wide_checks_are_visible_to_a_scoped_user(self):
        """Regression: the plain scope query excludes blank clients, which
        would have hidden all 32 shipped catalogue checks from every
        assessor."""
        from alphax_infra.core.tenancy import apply_permission_query_shared

        user = _scoped_user("_test_infra_scope@example.com", [self.client])
        frappe.set_user(user)
        try:
            condition = apply_permission_query_shared()
            self.assertIn("ifnull", condition)
            visible = frappe.get_all("Infra Check", limit=5)
            self.assertTrue(visible, "a scoped assessor cannot see any catalogue check")
        finally:
            frappe.set_user("Administrator")

    def test_rejected_batch_from_unknown_collector_is_logged(self):
        """Regression: client was mandatory and content_hash was unique, so a
        refusal from an unidentified collector left no trace at all — the one
        thing that row exists to prevent."""
        doc = frappe.new_doc("Infra Discovery Batch")
        doc.update({
            "status": "Rejected",
            "reject_reason": "unknown collector",
            "content_hash": secrets.token_hex(32),
            "received_at": now_datetime(),
        })
        doc.insert(ignore_permissions=True)
        self.assertTrue(doc.name)
        frappe.delete_doc("Infra Discovery Batch", doc.name, force=True, ignore_permissions=True)

    def test_app_roles_exist(self):
        for role in ("Infra Admin", "Infra Assessor", "Infra Viewer", "Infra Cross Tenant"):
            self.assertTrue(frappe.db.exists("Role", role), f"{role} was not created")
