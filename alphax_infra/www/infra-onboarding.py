# Copyright (c) 2026, Neotec Integrated Solutions
"""
Customer-facing onboarding page.

Three tiers, in descending order of how automatic they are, and the page says
so plainly rather than implying a browser link can reach a private network:

  1  Cloud       one click, Microsoft admin consent, fully automatic
  2  On-premises one command, run by their admin inside the network
  3  The rest    a questionnaire for what nothing can discover

Tier 2 exists because the browser sandbox stops a web page from enumerating the
machine it runs on or the LAN around it. That is not a limitation of this
product; it is why the web is safe to use. Something must execute inside the
perimeter, and the honest thing is to say so on the same page rather than after
the engagement starts.
"""

import frappe

no_cache = 1


def get_context(context):
    context.no_cache = 1
    session_name = frappe.form_dict.get("s")
    context.status_flag = frappe.form_dict.get("status")
    context.session = None

    if not session_name or not frappe.db.exists("Infra Assessment Session", session_name):
        context.invalid = True
        return context

    session = frappe.get_doc("Infra Assessment Session", session_name)
    if session.status in ("Expired", "Cancelled"):
        context.invalid = True
        context.reason = f"This assessment link is {session.status.lower()}."
        return context

    from alphax_infra.oauth import consent_url, requested_scopes, settings

    context.invalid = False
    context.session = session
    context.session_name = session.name
    context.organisation = frappe.db.get_value(
        "GRC Client Profile", session.client, "client_name"
    ) or session.client
    context.title = session.session_title
    context.purpose = session.purpose
    context.scope_summary = session.scope_summary
    context.scopes = requested_scopes()
    context.configured = bool((settings().get("mt_client_id") or "").strip())
    context.consent_url = consent_url(session.name) if context.configured else None

    # Never collected, stated before anything is authorised rather than buried
    # in a privacy notice afterwards.
    context.not_collected = [
        "Passwords, password hashes, private keys or certificate material",
        "Mailbox contents, files, documents or chat messages",
        "Network traffic or packet contents",
        "Personal data beyond the account identifiers needed to test access controls",
    ]

    grant = frappe.db.get_value(
        "Infra Tenant Grant", {"session": session.name},
        ["status", "tenant_domain"], as_dict=True, order_by="creation desc",
    )
    context.grant = grant
    return context
