"""Omada Open API (Northbound API) client.

Supports the official Omada Open API using both OAuth2 authentication
modes documented in the TP-Link Open API Access Guide:

* **Client Credentials Mode** — direct token exchange using
  ``client_id``, ``client_secret``, and ``omadacId``.
* **Authorization Code Mode** — three-step flow: login with user
  credentials, obtain an authorization code, then exchange for a token.

The base-path prefix is ``/openapi/v1/{omadacId}/…`` (or ``/openapi/v2/``
for a handful of newer endpoints).

This module provides:

* :func:`discover_controller_id` — ``GET /api/info`` to find omadacId.
* :func:`openapi_login` — Client Credentials Mode token exchange.
* :func:`openapi_auth_code_login` — Authorization Code Mode (3-step).
* :func:`openapi_discover_site` / :func:`openapi_discover_site_id` — list
  sites and select one by name.
* :class:`OmadaOpenApiClient` — paced, rate-limit-aware HTTP client with
  pagination, credential redaction, and a few single-endpoint getters.
  Subclass it (or call :meth:`~OmadaOpenApiClient.get` /
  :meth:`~OmadaOpenApiClient.get_paged` directly) for anything else.
"""

from __future__ import annotations

import logging
import os
import time
import warnings
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3

from omada_openapi.redaction import REDACTED, redact_secrets  # noqa: F401  (REDACTED re-exported)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

class OmadaAPIError(Exception):
    """Raised when the Omada controller returns an error response."""

    def __init__(self, error_code: int, message: str) -> None:
        self.error_code = error_code
        super().__init__(f"Omada API error {error_code}: {message}")


#: Omada's "too many requests" error code (its API rate limit).
RATE_LIMIT_ERROR_CODE = -7132
#: Default minimum gap between API calls, in seconds (``OMADA_REQUEST_INTERVAL``).
DEFAULT_REQUEST_INTERVAL = 0.2
#: The gap never grows beyond this, however often the controller pushes back.
MAX_REQUEST_INTERVAL = 2.0
#: Retries of one call after a rate-limit response before giving up.
RATE_LIMIT_RETRIES = 6
#: First backoff delay in seconds; doubled on each retry, capped below.
RATE_LIMIT_BACKOFF = 2.0
RATE_LIMIT_MAX_BACKOFF = 60.0

# Indirection so tests can skip real waiting.
_sleep = time.sleep
_monotonic = time.monotonic


def _request_interval_from_env() -> float:
    raw = os.environ.get("OMADA_REQUEST_INTERVAL", "").strip()
    if not raw:
        return DEFAULT_REQUEST_INTERVAL
    try:
        return max(0.0, float(raw))
    except ValueError:
        logger.warning("Ignoring OMADA_REQUEST_INTERVAL=%r (not a number); using %.1fs",
                       raw, DEFAULT_REQUEST_INTERVAL)
        return DEFAULT_REQUEST_INTERVAL


def _retry_after(resp: requests.Response) -> float | None:
    """Seconds from a numeric ``Retry-After`` header, if the server sent one."""
    try:
        value = float(resp.headers.get("Retry-After", ""))
    except (TypeError, ValueError, AttributeError):
        return None
    return value if value >= 0 else None


def _send_with_rate_limit(
    label: str,
    send: Any,
    on_limited: Any = None,
) -> requests.Response:
    """Call *send()* until the controller stops answering "too many requests".

    Omada rate-limits its API and answers with ``errorCode -7132`` (or HTTP
    429).  Those responses are retried up to :data:`RATE_LIMIT_RETRIES` times
    with exponential backoff, honouring a ``Retry-After`` header.  Any other
    response, success or error, is returned to the caller unchanged.
    *on_limited(attempt, wait)* is called before each wait; by default a
    warning is logged.
    """
    delay = RATE_LIMIT_BACKOFF
    for attempt in range(1, RATE_LIMIT_RETRIES + 2):
        resp = send()
        message = "too many requests"
        if resp.status_code != 429:
            try:
                body = resp.json()
            except ValueError:
                return resp
            if not (isinstance(body, dict) and body.get("errorCode") == RATE_LIMIT_ERROR_CODE):
                return resp
            message = body.get("msg", message)
        if attempt > RATE_LIMIT_RETRIES:
            raise OmadaAPIError(
                RATE_LIMIT_ERROR_CODE,
                f"{message} (still rate limited after {RATE_LIMIT_RETRIES} retries; "
                "wait a few minutes, or raise OMADA_REQUEST_INTERVAL)",
            )
        hint = _retry_after(resp)
        wait = min(RATE_LIMIT_MAX_BACKOFF, delay if hint is None else max(hint, delay))
        if on_limited is not None:
            on_limited(attempt, wait)
        else:
            logger.warning("Controller rate limit hit on %s; retrying in %.0fs (attempt %d of %d)",
                           label, wait, attempt, RATE_LIMIT_RETRIES)
        _sleep(wait)
        delay = min(RATE_LIMIT_MAX_BACKOFF, delay * 2)
    raise AssertionError("unreachable")  # pragma: no cover


def _make_session(verify_ssl: bool, base_url: str) -> requests.Session:
    """Create a :class:`requests.Session` with optional TLS verification."""
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    if not verify_ssl:
        sess.verify = False
        warnings.warn(
            f"TLS certificate verification is disabled for {base_url}. "
            "This makes the connection vulnerable to MITM attacks.",
            urllib3.exceptions.InsecureRequestWarning,
            stacklevel=3,
        )
    return sess


def discover_controller_id(
    base_url: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> str:
    """Discover the controller ID (``omadacId``) from ``GET /api/info``.

    This endpoint is unauthenticated and works regardless of auth mode.
    """
    url = base_url.rstrip("/") + "/api/info"
    sess = _make_session(verify_ssl, base_url)
    resp = _send_with_rate_limit("/api/info", lambda: sess.get(url, timeout=timeout))
    resp.raise_for_status()
    body = resp.json()
    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))
    result = body.get("result", {})
    cid = result.get("omadacId", "")
    if not cid:
        raise RuntimeError(
            "Could not determine controller ID: 'omadacId' not found "
            "in /api/info response"
        )
    logger.info("Discovered controller ID: %s", cid)
    return cid


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

@dataclass
class OpenApiLoginResult:
    """Result of a successful login (either auth mode)."""

    access_token: str
    session: requests.Session
    base_url: str


def openapi_login(
    base_url: str,
    omadac_id: str,
    client_id: str,
    client_secret: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> OpenApiLoginResult:
    """Authenticate via **Client Credentials Mode** and return a session.

    Endpoint: ``POST /openapi/authorize/token?grant_type=client_credentials``

    Parameters
    ----------
    base_url:
        Controller base URL, e.g. ``https://192.168.1.1:8043``.
    omadac_id:
        The Omada controller ID.
    client_id, client_secret:
        Open API application credentials.
    """
    sess = _make_session(verify_ssl, base_url)
    base = base_url.rstrip("/")
    token_url = f"{base}/openapi/authorize/token"

    resp = _send_with_rate_limit("token", lambda: sess.post(
        token_url,
        params={"grant_type": "client_credentials"},
        json={
            "omadacId": omadac_id,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=timeout,
    ))
    resp.raise_for_status()
    body = resp.json()

    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))

    result = body.get("result", {})
    access_token = result.get("accessToken", "")
    if not access_token:
        raise RuntimeError(
            "Open API login succeeded but no accessToken was returned"
        )

    sess.headers.update({"Authorization": f"AccessToken={access_token}"})
    logger.info("Client Credentials login successful — token obtained")
    return OpenApiLoginResult(
        access_token=access_token, session=sess, base_url=base,
    )


def openapi_auth_code_login(
    base_url: str,
    omadac_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> OpenApiLoginResult:
    """Authenticate via **Authorization Code Mode** (3-step) and return a session.

    Steps per TP-Link Open API docs §2.2:

    1. ``POST /openapi/authorize/login`` — log in with user credentials.
    2. ``POST /openapi/authorize/code``  — obtain an authorization code.
    3. ``POST /openapi/authorize/token`` — exchange the code for a token.

    Parameters
    ----------
    base_url:
        Controller base URL, e.g. ``https://192.168.1.1:8043``.
    omadac_id:
        The Omada controller ID.
    client_id, client_secret:
        Open API application credentials.
    username, password:
        Omada controller user credentials.
    """
    sess = _make_session(verify_ssl, base_url)
    base = base_url.rstrip("/")

    # Step 1 — Login
    login_url = f"{base}/openapi/authorize/login"
    login_resp = _send_with_rate_limit("login", lambda: sess.post(
        login_url,
        params={"client_id": client_id, "omadacId": omadac_id},
        json={"username": username, "password": password},
        timeout=timeout,
    ))
    login_resp.raise_for_status()
    login_body = login_resp.json()

    login_error = login_body.get("errorCode", -1)
    if login_error != 0:
        raise OmadaAPIError(login_error, login_body.get("msg", "login failed"))

    login_result = login_body.get("result", {})
    csrf_token = login_result.get("csrfToken", "")
    session_id = login_result.get("sessionId", "")
    if not csrf_token or not session_id:
        raise RuntimeError(
            "Authorization Code login succeeded but csrfToken/sessionId missing"
        )

    # Step 2 — Obtain authorization code
    code_url = f"{base}/openapi/authorize/code"
    code_resp = _send_with_rate_limit("authorize code", lambda: sess.post(
        code_url,
        params={
            "client_id": client_id,
            "omadacId": omadac_id,
            "response_type": "code",
        },
        headers={
            "Csrf-Token": csrf_token,
            "Cookie": f"TPOMADA_SESSIONID={session_id}",
        },
        timeout=timeout,
    ))
    code_resp.raise_for_status()
    code_body = code_resp.json()

    code_error = code_body.get("errorCode", -1)
    if code_error != 0:
        raise OmadaAPIError(code_error, code_body.get("msg", "authorize failed"))

    auth_code = code_body.get("result", "")
    if not auth_code:
        raise RuntimeError(
            "Authorization Code grant succeeded but no code was returned"
        )

    # Step 3 — Exchange authorization code for access token
    token_url = f"{base}/openapi/authorize/token"
    token_resp = _send_with_rate_limit("token", lambda: sess.post(
        token_url,
        params={
            "grant_type": "authorization_code",
            "code": auth_code,
        },
        json={
            "omadacId": omadac_id,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=timeout,
    ))
    token_resp.raise_for_status()
    token_body = token_resp.json()

    token_error = token_body.get("errorCode", -1)
    if token_error != 0:
        raise OmadaAPIError(token_error, token_body.get("msg", "token exchange failed"))

    token_result = token_body.get("result", {})
    access_token = token_result.get("accessToken", "")
    if not access_token:
        raise RuntimeError(
            "Authorization Code token exchange succeeded but no accessToken "
            "was returned"
        )

    # Prepare session for subsequent API calls
    sess.headers.update({"Authorization": f"AccessToken={access_token}"})
    # Clear login cookies — we only need the bearer token going forward
    sess.cookies.clear()
    logger.info("Authorization Code login successful — token obtained")
    return OpenApiLoginResult(
        access_token=access_token, session=sess, base_url=base,
    )


def openapi_discover_site(
    base_url: str,
    omadac_id: str,
    session: requests.Session,
    *,
    site_name: str = "",
    timeout: int = 30,
) -> tuple[str, str]:
    """Discover a site's ID and display name via the Open API.

    Parameters
    ----------
    session:
        An authenticated session from :func:`openapi_login`.
    site_name:
        Human-readable site name to match (case-insensitive).

    Returns
    -------
    tuple[str, str]
        The site ID and display name.
    """
    url = (
        f"{base_url.rstrip('/')}/openapi/v1/{omadac_id}/sites"
        "?page=1&pageSize=1000"
    )
    resp = _send_with_rate_limit("sites", lambda: session.get(url, timeout=timeout))
    resp.raise_for_status()
    body = resp.json()

    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))

    result = body.get("result", {})
    if isinstance(result, dict):
        sites = result.get("data", [])
    elif isinstance(result, list):
        sites = result
    else:
        raise RuntimeError("Unexpected response format from Open API /sites")

    if not sites:
        raise RuntimeError("No sites found via Open API")

    needle = site_name.strip().casefold()
    if needle:
        for s in sites:
            if s.get("name", "").strip().casefold() == needle:
                site_id = s.get("siteId", s.get("id", ""))
                logger.info(
                    "Matched site by name: %s (%s)", s.get("name"), site_id,
                )
                return site_id, s.get("name", "")
        available = ", ".join(s.get("name", "?") for s in sites)
        raise RuntimeError(
            f"No site named '{site_name.strip()}' found. "
            f"Available sites: {available}"
        )

    if len(sites) == 1:
        site_id = sites[0].get("siteId", sites[0].get("id", ""))
        logger.info(
            "Auto-selected site: %s (%s)", sites[0].get("name"), site_id,
        )
        return site_id, sites[0].get("name", "")

    lines = ["Multiple sites found. Please select a site by name or id:"]
    for s in sites:
        sid = s.get("siteId", s.get("id", "?"))
        lines.append(f"  • {s.get('name', '?')}  (id: {sid})")
    raise RuntimeError("\n".join(lines))


def openapi_discover_site_id(
    base_url: str,
    omadac_id: str,
    session: requests.Session,
    *,
    site_name: str = "",
    timeout: int = 30,
) -> str:
    """Discover a site ID via the Open API."""
    site_id, _ = openapi_discover_site(
        base_url,
        omadac_id,
        session,
        site_name=site_name,
        timeout=timeout,
    )
    return site_id


def normalize_mac(mac: Any) -> str:
    """Normalize a MAC address for comparison (``aa:bb`` → ``AA-BB``)."""
    return str(mac).strip().upper().replace(":", "-")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OmadaOpenApiClient:
    """HTTP client for the Omada Open API (Northbound API).

    Every call is paced (see *request_interval*) and retried with backoff
    while the controller answers "too many requests".  Use :meth:`get`,
    :meth:`post` and :meth:`get_paged` for any Open API path; the ``get_*``
    methods cover a few common endpoints.

    Parameters
    ----------
    base_url:
        Controller / cloud base URL.
    omadac_id:
        The Omada controller ID.
    access_token:
        A valid access token from :func:`openapi_login`.
    verify_ssl:
        Whether to verify TLS certificates.
    timeout:
        Request timeout in seconds.
    session:
        An authenticated :class:`requests.Session` (from
        :func:`openapi_login`).
    """

    def __init__(
        self,
        base_url: str,
        omadac_id: str,
        access_token: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
        session: requests.Session | None = None,
        request_interval: float | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        #: Minimum seconds between API calls.  Starts at *request_interval*
        #: (default ``$OMADA_REQUEST_INTERVAL`` or 0.2s) and widens when the
        #: controller answers "too many requests".
        self.request_interval = (
            _request_interval_from_env() if request_interval is None else max(0.0, request_interval)
        )
        self._last_request: float | None = None
        self._rate_limit_warned = False
        self.omadac_id = omadac_id
        #: When True, :meth:`redact` returns data unchanged instead of
        #: masking credentials.
        self.include_secrets = False
        self.access_token = access_token
        self.timeout = timeout

        if session is not None:
            self._session = session
        else:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"AccessToken={access_token}",
                "Content-Type": "application/json",
            })
            if not verify_ssl:
                self._session.verify = False
                warnings.warn(
                    f"TLS certificate verification is disabled for {base_url}. "
                    "This makes the connection vulnerable to MITM attacks.",
                    urllib3.exceptions.InsecureRequestWarning,
                    stacklevel=2,
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def redact(self, data: Any) -> Any:
        """Redact credentials in *data* unless :attr:`include_secrets` is set."""
        return data if self.include_secrets else redact_secrets(data)

    def _api_url(self, path: str, *, api_version: str = "v1") -> str:
        """Build a full URL from a relative Open API *path*."""
        prefix = f"/openapi/{api_version}/{self.omadac_id}/"
        relative = path.lstrip("/")
        return urljoin(self.base_url + prefix, relative)

    def _throttle(self) -> None:
        """Wait until at least :attr:`request_interval` has passed since the last call."""
        if self._last_request is not None and self.request_interval > 0:
            wait = self._last_request + self.request_interval - _monotonic()
            if wait > 0:
                _sleep(wait)
        self._last_request = _monotonic()

    def _on_rate_limited(self, path: str, attempt: int, delay: float) -> None:
        """Slow down for the rest of the run and log the first occurrence."""
        self.request_interval = min(MAX_REQUEST_INTERVAL, max(self.request_interval * 2, 0.5))
        log = logger.debug if self._rate_limit_warned else logger.warning
        self._rate_limit_warned = True
        log(
            "Controller rate limit hit on %s; waiting %.0fs and retrying (attempt %d of %d). "
            "Calls are now spaced %.1fs apart.",
            path, delay, attempt, RATE_LIMIT_RETRIES, self.request_interval,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        api_version: str = "v1",
    ) -> dict[str, Any]:
        """Send one paced API call, retried while rate limited; return the body.

        Every call waits for :attr:`request_interval` since the previous one.
        A "too many requests" answer is retried with backoff (see
        :func:`_send_with_rate_limit`) and widens the interval for the rest of
        the run, so a long export finishes instead of losing resources.
        """
        url = self._api_url(path, api_version=api_version)

        def send() -> requests.Response:
            self._throttle()
            if method == "POST":
                logger.debug("OPENAPI POST %s", url)
                return self._session.post(url, json=payload, timeout=self.timeout)
            logger.debug("OPENAPI GET %s params=%s", url, params)
            return self._session.get(url, params=params or {}, timeout=self.timeout)

        resp = _send_with_rate_limit(
            path, send, lambda attempt, wait: self._on_rate_limited(path, attempt, wait),
        )
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        logger.debug(
            "OpenAPI response for %s: status=%d, body keys=%s",
            path, resp.status_code,
            list(body.keys()) if isinstance(body, dict) else type(body).__name__,
        )
        if isinstance(body, dict) and "errorCode" in body and body["errorCode"] != 0:
            raise OmadaAPIError(body["errorCode"], body.get("msg", "unknown error"))
        return body

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        api_version: str = "v1",
    ) -> Any:
        """GET an Open API *path* and return the response's ``result`` payload.

        *path* is relative to ``/openapi/{api_version}/{omadacId}/``.  Raises
        :class:`OmadaAPIError` when the controller reports an error.
        """
        body = self._request("GET", path, params=params, api_version=api_version)
        result = body.get("result", body)
        if isinstance(result, dict):
            logger.debug("OpenAPI result for %s: keys=%s", path, list(result.keys()))
        elif isinstance(result, list):
            logger.debug("OpenAPI result for %s: list with %d item(s)", path, len(result))
        return result

    def post(self, path: str, payload: dict[str, Any], *, api_version: str = "v1") -> Any:
        """POST *payload* to an Open API *path* and return the ``result`` payload.

        Several read endpoints take their query in the body (e.g.
        ``switches/ports/select``).
        """
        body = self._request("POST", path, payload=payload, api_version=api_version)
        return body.get("result", body)

    def get_paged(
        self,
        path: str,
        *,
        page_size: int = 100,
        max_pages: int = 200,
        api_version: str = "v1",
    ) -> list[dict[str, Any]]:
        """Fetch every page of a paginated Open API endpoint into one list.

        The Open API uses ``page`` and ``pageSize`` query parameters
        (as opposed to ``currentPage``/``currentPageSize``).
        """
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            params = {"page": page, "pageSize": page_size}
            result = self.get(path, params=params, api_version=api_version)

            if isinstance(result, list):
                items.extend(result)
                break

            data = result.get("data", [])
            if not data and page == 1 and isinstance(result, dict):
                # Auto-detect: find any value that is a non-empty list of dicts
                for key, val in result.items():
                    if (
                        key not in ("totalRows", "currentPage", "currentSize")
                        and isinstance(val, list)
                        and val
                        and isinstance(val[0], dict)
                    ):
                        data = val
                        logger.debug(
                            "OpenAPI pagination for %s: auto-detected data "
                            "under '%s' key (%d item(s))",
                            path, key, len(val),
                        )
                        break

            items.extend(data)
            total_rows = result.get("totalRows", len(items))
            if len(items) >= total_rows:
                break
        else:
            logger.warning(
                "OpenAPI pagination reached max_pages=%d for %s; "
                "%d record(s) collected.",
                max_pages, path, len(items),
            )
        return items

    # ------------------------------------------------------------------
    # Common endpoints
    # ------------------------------------------------------------------

    def get_devices(self, site_id: str) -> list[dict[str, Any]]:
        """Return the adopted devices for the given site.

        Endpoint: ``GET /sites/{siteId}/devices``
        """
        return self.get_paged(f"sites/{site_id}/devices")

    def get_networks(self, site_id: str) -> list[dict[str, Any]]:
        """Return all LAN networks for the given site.

        Endpoint: ``GET /sites/{siteId}/lan-networks/all``, falling back to the
        paginated ``GET /sites/{siteId}/lan-networks``.
        """
        try:
            result = self.get(f"sites/{site_id}/lan-networks/all")
            return result if isinstance(result, list) else []
        except OmadaAPIError:
            return self.get_paged(f"sites/{site_id}/lan-networks")

    def get_dhcp_leases(self, site_id: str) -> list[dict[str, Any]]:
        """Return current DHCP leases across all DHCP servers in the site.

        Endpoint: ``GET /sites/{siteId}/setting/service/dhcp/user-list``
        """
        return self.get_paged(f"sites/{site_id}/setting/service/dhcp/user-list")
