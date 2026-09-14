# One-time setup: the multi-tenant application

Done once, in Neotec's own Entra tenant. Every customer afterwards is one link
and one click.

## 1. Register the application

Entra admin centre → App registrations → New registration.

- Name: `AlphaX Infra Discovery`
- Supported account types: **Accounts in any organizational directory
  (multitenant)**. This is the setting the whole flow depends on.
- Redirect URI: **Web** →
  `https://neo15.k.frappe.cloud/api/method/alphax_infra.oauth.callback`

## 2. Add read-only application permissions

API permissions → Microsoft Graph → **Application permissions**. Not delegated —
discovery runs without a signed-in user.

**Entra ID:** `User.Read.All`, `Group.Read.All`, `Directory.Read.All`,
`UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`,
`Application.Read.All`, `RoleManagement.Read.Directory`

**Intune:** `DeviceManagementManagedDevices.Read.All`,
`DeviceManagementConfiguration.Read.All`, `Device.Read.All`

Add nothing beyond these. Customers' security teams read the consent screen, and
a single write permission on that list will end the conversation — correctly.

Then: **Grant admin consent** for the Neotec tenant.

## 3. Create a client secret

Certificates & secrets → New client secret. Copy the **Value** immediately; it is
shown once.

This is Neotec's own credential, and the only one the flow uses. It is never a
customer's.

## 4. Record it

AlphaX Infra Settings → Multi-tenant Onboarding: client ID and secret. Leave the
reply URL blank unless the site is behind a different public hostname, in which
case it must match the registration exactly.

## 5. Per engagement

1. Create a `GRC Client Profile` for the customer.
2. Create an `Infra Assessment Session` and set its scope.
3. Run `alphax_infra.oauth.get_consent_link` to get the portal URL.
4. Send the link.

Their Global Administrator opens it, reviews the permissions, signs in, and
accepts. Connectors are created and discovery begins.

## Azure needs one more step

Admin consent grants Graph permissions across the tenant. It does not grant a
role on an Azure **subscription** — those are separate, and no directory-level
consent can confer them. The customer assigns `Reader` on the subscription to
the `AlphaX Infra Discovery` service principal, then you create the Azure
connector with the subscription ID.

This is why Azure is deliberately excluded from automatic provisioning: an
auto-created Azure connector would fail on every run and look like a product
defect rather than a missing role assignment.

## What to tell a security team that pushes back

- Every permission is `.Read.`. None permits a change.
- No credential was created in their tenant and nothing was sent to us.
- The service principal appears in their Enterprise Applications and can be
  deleted there at any time, which stops collection immediately.
- Authentication methods are read as *kinds only* — that a strong factor is
  registered, never the phone number or device.
- Mailbox, file and message contents are not in scope of any requested
  permission.

## If it fails

**Redirected but nothing happened** — check `Infra Tenant Grant` for the
session. `Denied` means they cancelled. `Failed` means consent was recorded but
no token could be obtained; the detail field says why.

**"Need admin approval"** — the person who opened the link is not a Global
Administrator. Only they can grant tenant-wide consent.

**Grant stuck at `Granted`** — activation retries six times over about two
minutes for Microsoft's service principal to propagate. Longer than that is a
real failure and is written to the error log.
