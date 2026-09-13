# Copyright (c) 2026, Neotec Integrated Solutions

app_name = "alphax_infra"
app_title = "AlphaX Infra"
app_publisher = "Neotec Integrated Solutions"
app_description = "IT infrastructure discovery and control assessment for AlphaX GRC"
app_email = "support@irsaa.com"
app_license = "MIT"
app_version = "0.1.0"

# Hard dependency. This app deliberately does not carry its own control
# library, evidence model or client register — it extends the GRC app's.
# Declaring it here makes bench refuse the install rather than letting a site
# end up with half a product.
required_apps = ["alphax_grc"]

before_install = "alphax_infra.install.before_install"
after_install = "alphax_infra.install.after_install"
after_migrate = "alphax_infra.install.after_migrate"

app_include_css = ["/assets/alphax_infra/css/infra.css"]

# ---------------------------------------------------------------------------
# Tenancy
#
# Every client-scoped doctype is filtered by the same rule as the API. Without
# these entries a list view, a report or an export would each be a separate
# cross-tenant leak, because User Permissions alone do not follow raw queries.
# ---------------------------------------------------------------------------
_SCOPED = (
    "Infra Connector",
    "Infra Collector",
    "Infra Discovery Job",
    "Infra Discovery Batch",
    "Infra Asset",
    "Infra Asset Relationship",
    "Infra Merge Proposal",
    "Infra Check",            # client-scoped: a check may be tuned for one client
    "Infra Check Result",
    "Infra Assessment Session",
    "Infra Consent Record",
    "Infra Access Log",
)

permission_query_conditions = {
    dt: "alphax_infra.core.tenancy.apply_permission_query" for dt in _SCOPED
}

has_permission = {dt: "alphax_infra.core.tenancy.has_doc_permission" for dt in _SCOPED}

# ---------------------------------------------------------------------------
# Scheduled jobs
# ---------------------------------------------------------------------------
scheduler_events = {
    "daily_long": [
        "alphax_infra.tasks.run_scheduled_connectors",
        "alphax_infra.tasks.evaluate_daily_checks",
    ],
    "daily": [
        "alphax_infra.tasks.expire_consent_records",
        "alphax_infra.tasks.expire_assessment_sessions",
        "alphax_infra.tasks.alert_stale_collectors",
        "alphax_infra.tasks.alert_critical_failures",
    ],
    "weekly_long": [
        "alphax_infra.tasks.purge_expired_observations",
    ],
}

# ---------------------------------------------------------------------------
# Document events
# ---------------------------------------------------------------------------
doc_events = {
    "Infra Asset": {
        "on_trash": "alphax_infra.tasks.guard_asset_deletion",
    },
}

# ---------------------------------------------------------------------------
# Fixtures
#
# Intentionally empty. Roles and the check catalogue are seeded through
# install.py, which can express "create if missing, never overwrite" —
# fixtures overwrite on every migrate and would reset client-tuned checks.
# ---------------------------------------------------------------------------
fixtures = []
