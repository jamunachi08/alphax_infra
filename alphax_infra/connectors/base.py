# Copyright (c) 2026, Neotec Integrated Solutions
"""
Connector framework.

Every connector is a module that turns a vendor API into normalised
observations. It does four things and nothing else: authenticate, page,
normalise, redact. It does not score, does not create findings, and does not
decide compliance — those happen downstream against the observation store, so
the same check works whether a fact came from Graph, a collector or a
questionnaire.

The design constraints that matter:

- Read-only scopes only. A connector that requests write permission will not
  pass the definition-of-done review, and customers' security teams read the
  consent screen.
- Redact before storing, not before displaying. Once a secret is in the
  database it is in the backups. `REDACT_KEYS` is applied to every payload on
  the way in.
- Never raise into the caller. A vendor outage must degrade one connector, not
  abort a discovery run. Failures come back as a ConnectorResult with an error.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import frappe
import requests

REGISTRY: dict[str, "ConnectorSpec"] = {}

DEFAULT_TIMEOUT = 30
MAX_PAGES = 200
USER_AGENT = "AlphaX-Infra/0.1.0 (+https://neotec.sa)"

# Anything whose key looks like a secret is dropped before the value is
# serialised. Matched on the key, case-insensitive, at every nesting level.
REDACT_PATTERNS = (
    r"secret",
    r"password",
    r"passwd",
    r"credential",
    r"private[_-]?key",
    r"client[_-]?secret",
    r"access[_-]?token",
    r"refresh[_-]?token",
    r"id[_-]?token",
    r"shared[_-]?key",
    r"connection[_-]?string",
    r"sas[_-]?token",
    r"certificate[_-]?data",
    r"pfx",
    r"api[_-]?key",
    r"authorization",
    r"pre[_-]?shared",
)
_REDACT_RE = re.compile("|".join(REDACT_PATTERNS), re.IGNORECASE)
REDACTED = "[redacted by connector]"


@dataclass
class ConnectorSpec:
    key: str
    label: str
    vendor: str
    scopes: tuple
    fetch: Callable
    description: str = ""


@dataclass
class ConnectorResult:
    ok: bool = True
    observations: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    error: str | None = None
    pages: int = 0
    api_calls: int = 0
    notes: dict = field(default_factory=dict)

    def observe(self, subject: str, fact_key: str, value: Any, **kw) -> None:
        self.observations.append(
            {
                "subject": subject,
                "fact_key": fact_key,
                "value": redact(value),
                "asset": kw.get("asset"),
                "source_ref": kw.get("source_ref"),
                "confidence": kw.get("confidence", 100),
            }
        )

    def asset(self, asset_type: str, name: str, identifiers: list, **fields) -> None:
        self.assets.append(
            {
                "asset_type": asset_type,
                "asset_name": name,
                "identifiers": identifiers,
                **fields,
            }
        )


def register(key: str, label: str, vendor: str, scopes: tuple, description: str = ""):
    def decorator(fn):
        REGISTRY[key] = ConnectorSpec(
            key=key, label=label, vendor=vendor, scopes=scopes, fetch=fn, description=description
        )
        return fn

    return decorator


def get(key: str) -> ConnectorSpec | None:
    return REGISTRY.get(key)


def available() -> list[dict]:
    return [
        {
            "key": s.key,
            "label": s.label,
            "vendor": s.vendor,
            "scopes": list(s.scopes),
            "description": s.description,
        }
        for s in sorted(REGISTRY.values(), key=lambda x: (x.vendor, x.label))
    ]


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def redact(value: Any, _depth: int = 0) -> Any:
    if _depth > 12:
        return "[truncated: nesting depth]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = REDACTED if _REDACT_RE.search(str(k)) else redact(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value[:1000]]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "…[truncated]"
    return value


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def credentials(connector_name: str) -> dict:
    """
    Read a connector's secret out of Frappe's password store.

    Secrets live in a Password field on Infra Connector, never in a Data field
    and never in the observation store. `get_password` reads the encrypted
    value; it is used here and nowhere else in the app.
    """
    doc = frappe.get_doc("Infra Connector", connector_name)
    secret = doc.get_password("client_secret", raise_exception=False) or ""
    return {
        "tenant_id": doc.tenant_id,
        "client_id": doc.client_id,
        "client_secret": secret,
        "base_url": doc.base_url,
        "subscription_id": doc.subscription_id,
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class ConnectorError(Exception):
    pass


def oauth_token(tenant_id: str, client_id: str, client_secret: str, scope: str) -> str:
    """Client-credentials grant. Used by Graph and by Azure Resource Manager."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(
        url,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": scope,
        },
        timeout=DEFAULT_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    if resp.status_code != 200:
        # Deliberately does not echo the response body: failed token responses
        # sometimes contain the submitted client_id and assertion fragments.
        raise ConnectorError(f"token request failed with HTTP {resp.status_code}")
    token = resp.json().get("access_token")
    if not token:
        raise ConnectorError("token response contained no access_token")
    return token


def get_paged(
    url: str,
    token: str,
    result: ConnectorResult,
    *,
    params: dict | None = None,
    next_key: str = "@odata.nextLink",
    items_key: str = "value",
    max_pages: int = MAX_PAGES,
) -> list:
    """
    Follow a vendor's paging cursor, honouring 429 Retry-After.

    Backing off on throttle rather than hammering is not politeness: a
    connector that gets a tenant's app registration rate-limited is a
    connector the customer disables.
    """
    items: list = []
    headers = {"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT}
    pages = 0

    while url and pages < max_pages:
        resp = requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        result.api_calls += 1
        params = None  # only on the first request; nextLink carries its own

        if resp.status_code == 429:
            wait = min(int(resp.headers.get("Retry-After", "5") or 5), 60)
            time.sleep(wait)
            continue
        if resp.status_code == 403:
            raise ConnectorError(
                "permission denied — the app registration is missing a required "
                "read scope for this endpoint"
            )
        if resp.status_code == 401:
            raise ConnectorError("authentication rejected — credentials expired or revoked")
        if resp.status_code >= 400:
            raise ConnectorError(f"HTTP {resp.status_code} from {url.split('?')[0]}")

        body = resp.json()
        items.extend(body.get(items_key) or [])
        url = body.get(next_key)
        pages += 1

    result.pages += pages
    if pages >= max_pages:
        result.notes["paging_truncated"] = f"stopped at {max_pages} pages"
    return items


def run(connector_key: str, connector_name: str) -> ConnectorResult:
    """Entry point used by Infra Discovery Job. Never raises."""
    spec = get(connector_key)
    if not spec:
        return ConnectorResult(ok=False, error=f"unknown connector: {connector_key}")
    try:
        creds = credentials(connector_name)
        if not creds.get("client_secret"):
            return ConnectorResult(ok=False, error="no credential configured on this connector")
        return spec.fetch(creds)
    except ConnectorError as exc:
        return ConnectorResult(ok=False, error=str(exc))
    except requests.RequestException as exc:
        return ConnectorResult(ok=False, error=f"network error: {type(exc).__name__}")
    except Exception:  # noqa: BLE001
        frappe.log_error(
            title=f"Infra connector crashed: {connector_key}"[:140],
            message=frappe.get_traceback(),
        )
        return ConnectorResult(ok=False, error="connector raised an unexpected error; see error log")
