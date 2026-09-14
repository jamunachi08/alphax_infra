# Copyright (c) 2026, Neotec Integrated Solutions
"""
Connector package.

Importing this package registers every shipped connector. Import order is the
registration order, so keep it alphabetical and keep side effects out of
module bodies beyond the @register decorator itself.
"""

from alphax_infra.connectors import azure, entra, m365  # noqa: F401
from alphax_infra.connectors.base import (  # noqa: F401
    ConnectorError,
    ConnectorResult,
    available,
    get,
    redact,
    register,
    run,
)

__all__ = [
    "ConnectorError",
    "ConnectorResult",
    "available",
    "get",
    "redact",
    "register",
    "run",
]
