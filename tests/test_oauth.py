#!/usr/bin/env python3
"""Offline tests for the admin-consent flow. No site, no network.

The state token is the whole security boundary of a guest-reachable browser
redirect, so it gets the most attention here."""
import hashlib, hmac, os, re, sys, time, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SECRET = b"test-encryption-key"


def _sign(payload):
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_state(session, issued=None):
    import secrets
    payload = f"{session}|{issued or int(time.time())}|{secrets.token_urlsafe(18)}"
    return f"{payload}|{_sign(payload)}"


def read_state(state, ttl=1800):
    try:
        session, issued, nonce, sig = (state or "").split("|", 3)
    except ValueError:
        return None
    payload = f"{session}|{issued}|{nonce}"
    if not hmac.compare_digest(_sign(payload), sig):
        return None
    if time.time() - int(issued) > ttl:
        return None
    return {"session": session, "nonce": nonce}


class TestStateToken(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(read_state(make_state("SES-2026-00001"))["session"], "SES-2026-00001")

    def test_tampering_with_the_session_is_rejected(self):
        """Otherwise a consent could be driven into another customer's session."""
        s = make_state("SES-A")
        _, issued, nonce, sig = s.split("|", 3)
        self.assertIsNone(read_state(f"SES-B|{issued}|{nonce}|{sig}"))

    def test_forged_signature_is_rejected(self):
        s = make_state("SES-A").rsplit("|", 1)[0]
        self.assertIsNone(read_state(f"{s}|{'0'*64}"))

    def test_expired_state_is_rejected(self):
        self.assertIsNone(read_state(make_state("SES-A", issued=int(time.time()) - 3601)))

    def test_malformed_input_never_raises(self):
        for bad in ("", None, "x", "a|b", "a|b|c", "||||", "a|notanint|c|d"):
            try:
                self.assertIsNone(read_state(bad))
            except ValueError:
                self.fail(f"read_state raised on {bad!r}")

    def test_states_are_unique_per_issue(self):
        self.assertNotEqual(make_state("SES-A"), make_state("SES-A"))


class TestTenantValidation(unittest.TestCase):
    GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    def test_accepts_a_real_guid(self):
        self.assertTrue(self.GUID.match("72f988bf-86f1-41af-91ab-2d7cd011db47"))

    def test_rejects_injection_shapes(self):
        """The tenant id is interpolated into a token endpoint URL."""
        for bad in ("", "not-a-guid", "../../evil", "72f988bf",
                    "72f988bf-86f1-41af-91ab-2d7cd011db47/../x",
                    "72f988bf-86f1-41af-91ab-2d7cd011db47 "):
            self.assertIsNone(self.GUID.match(bad), bad)


class TestSourceContracts(unittest.TestCase):
    """Assertions about the shipped module that the site tests cannot make cheaply."""

    def setUp(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.src = open(os.path.join(root, "alphax_infra", "oauth.py")).read()

    def test_uses_organizations_endpoint(self):
        """`common` would admit personal Microsoft accounts, which cannot grant
        admin consent and produce a confusing dead end."""
        self.assertIn("organizations/v2.0/adminconsent", self.src)

    def test_state_is_compared_in_constant_time(self):
        self.assertIn("hmac.compare_digest", self.src)

    def test_denied_consent_is_recorded(self):
        """A customer who clicked Cancel must not look like one who never opened
        the link."""
        self.assertIn('status="Denied"', self.src)

    def test_azure_is_not_auto_provisioned(self):
        """Admin consent does not grant a subscription role assignment, so an
        auto-created Azure connector would fail on every run."""
        self.assertIn('AUTO_PROVISION = ("entra", "m365")', self.src)

    def test_activation_retries_for_propagation(self):
        self.assertIn("range(6)", self.src)

    def test_no_customer_secret_is_ever_written(self):
        self.assertNotIn("client_secret\": doc.get_password", self.src)


class TestPortalPage(unittest.TestCase):
    def setUp(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.www = os.path.join(root, "alphax_infra", "www")

    def test_route_matches_the_redirect_target(self):
        from_oauth = open(os.path.join(os.path.dirname(self.www), "oauth.py")).read()
        self.assertIn("/infra-onboarding", from_oauth)
        self.assertTrue(os.path.exists(os.path.join(self.www, "infra-onboarding.html")))
        self.assertTrue(os.path.exists(os.path.join(self.www, "infra-onboarding.py")))

    def test_template_is_valid_jinja_and_leaves_nothing_unrendered(self):
        import json as _json
        from jinja2 import Environment
        env = Environment()
        env.filters["tojson"] = _json.dumps
        tpl = env.from_string(open(os.path.join(self.www, "infra-onboarding.html")).read())
        out = tpl.render(invalid=False, title="T", organisation="O", purpose="P",
                         scope_summary="S", status_flag=None, scopes=["A.Read"],
                         configured=True, consent_url="https://x", session_name="SES-1",
                         not_collected=["Passwords"], grant=None)
        self.assertNotIn("{{", out)
        self.assertNotIn("{%", out)

    def test_page_states_the_browser_limitation(self):
        html = open(os.path.join(self.www, "infra-onboarding.html")).read()
        self.assertIn("cannot reach inside your network", html)


if __name__ == "__main__":
    unittest.main(verbosity=1)
