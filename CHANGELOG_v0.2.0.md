# AlphaX Infra — v0.2.0

One-click customer onboarding through Microsoft admin consent.

## The change

Starting an engagement previously meant asking the customer to register an
application in their tenant, grant eight permissions, mint a client secret, and
send it to us. Four technical steps, a credential we then had to hold and
rotate, and a conversation that routinely stalled for a week.

Now: one application is registered once in the Neotec tenant, marked
multi-tenant, read-only. The customer's Global Administrator opens a link, signs
in with their normal account, reads Microsoft's own permission screen, and
accepts. Microsoft provisions a service principal in their tenant and redirects
back. Connectors are created and discovery starts automatically.

What this buys:

- **No customer credential is ever created or held.** There is nothing to leak,
  rotate, or return at the end of an engagement.
- **The permission list is rendered by Microsoft, not by us.** The customer's
  security team reads Microsoft's screen, which is the only version they have
  reason to trust.
- **Revocation is one click in their own Enterprise Applications blade**, with
  no involvement from us. That asymmetry is what makes the ask reasonable.

No connector code changed. An app-only token for a consented tenant is obtained
with our `client_id` and secret against the customer's token endpoint, which is
the shape `oauth_token` already took.

## Added

- `alphax_infra/oauth.py` — consent URL construction, HMAC-signed single-use
  state bound to one session, the redirect callback, background activation with
  retry for service-principal propagation, idempotent connector provisioning,
  and a status endpoint the portal polls.
- `Infra Tenant Grant` — the record of a consent: tenant, domain, who granted
  it, when it was verified, which connectors it provisioned. Setting it to
  Revoked immediately disables every connector that depends on it.
- `/infra-onboarding` — the customer-facing page. Three tiers, each honest about
  how automatic it is: cloud in one click; on-premises needing one command,
  because a browser cannot enumerate a private network and the page says so; and
  a questionnaire for what nothing can discover.
- `AlphaX Infra Settings` — multi-tenant application ID, secret and reply URL.
- `Infra Connector.auth_mode` — Admin Consent or Manual App Registration.
  Existing connectors default to Manual and are unaffected.

## Guard and tests

Three new `verify_tree` groups, now 29 in total:

- **guest endpoints are deliberate** — every `allow_guest=True` method is
  checked against an explicit list, so a new internet-reachable endpoint has to
  be added consciously rather than appearing in an unread diff.
- **the consent callback validates its inputs** — constant-time state
  comparison, GUID validation on the tenant id before it reaches a URL, and a
  state expiry.
- **www routes resolve** — a redirect target with no page would 404 the customer
  at the exact moment they had just authorised access.

17 new offline tests covering state forgery, session substitution, expiry,
malformed input, tenant-id injection shapes, and template rendering.

## Defects found during the build

- The portal template was wrapped in a Jinja `raw` block, which would have
  rendered the entire page as literal markup. The guard now rejects raw blocks
  in `www`.
- The page file was named with underscores while the callback redirected to a
  hyphenated route, so every successful consent would have landed on a 404.
  Caught by the new www-route check.
- `Infra Tenant Grant` had a `client` field but no `permission_query_conditions`
  entry — the same tenancy gap the guard caught on `Infra Check` in v0.1.1, on a
  new doctype. The guard caught it again.

## Before this works

Register one application in the Neotec Entra tenant:

1. Multi-tenant (accounts in any organizational directory).
2. Application permissions, read-only, matching the connector scopes.
3. Grant admin consent in your own tenant first.
4. Reply URL: `https://<your-site>/api/method/alphax_infra.oauth.callback`
5. Record the client ID and secret in AlphaX Infra Settings.

Azure is deliberately not auto-provisioned. Admin consent does not grant a
subscription role assignment, so an auto-created Azure connector would fail on
every run; it stays a separate explicit step.
