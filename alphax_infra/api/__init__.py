# Copyright (c) 2026, Neotec Integrated Solutions
"""External-facing endpoints. Everything under this package is reachable over
HTTP, so every function validates its own input and resolves its own tenant
scope rather than trusting the caller."""
