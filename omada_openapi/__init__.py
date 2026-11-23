"""Python client for the TP-Link Omada Open API (Northbound API)."""

from omada_openapi.client import (
    DEFAULT_REQUEST_INTERVAL,
    RATE_LIMIT_ERROR_CODE,
    TOKEN_ERROR_CODES,
    OmadaAPIError,
    OmadaOpenApiClient,
    OpenApiLoginResult,
    discover_controller_id,
    normalize_mac,
    openapi_auth_code_login,
    openapi_discover_site,
    openapi_discover_site_id,
    openapi_login,
    openapi_refresh_token,
)
from omada_openapi.redaction import REDACTED, contains_secrets, is_secret_key, redact_secrets

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_REQUEST_INTERVAL",
    "RATE_LIMIT_ERROR_CODE",
    "REDACTED",
    "TOKEN_ERROR_CODES",
    "OmadaAPIError",
    "OmadaOpenApiClient",
    "OpenApiLoginResult",
    "contains_secrets",
    "discover_controller_id",
    "is_secret_key",
    "normalize_mac",
    "openapi_auth_code_login",
    "openapi_discover_site",
    "openapi_discover_site_id",
    "openapi_login",
    "openapi_refresh_token",
    "redact_secrets",
]
