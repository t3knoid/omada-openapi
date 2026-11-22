# omada-openapi

A Python client for the **TP-Link Omada Open API** (Northbound API), the
official, documented API for Omada SDN controllers.

It handles the parts every Open API integration needs:

- **Authentication** — both official OAuth2 modes:
  - **Client Credentials Mode** — Client ID + Secret
  - **Authorization Code Mode** — three-step flow with a controller user
- **Discovery** — controller ID (`omadacId`) from `/api/info`, and site lookup
  by name
- **Rate limiting** — every call is paced, and the controller's "too many
  requests" answer (`errorCode -7132` or HTTP 429) is retried with
  exponential backoff, honouring `Retry-After`; the pacing widens for the rest
  of the run when the controller pushes back
- **Pagination** — `get_paged()` walks `page` / `pageSize` and returns one list
- **Credential redaction** — `redact()` masks passphrases, shared secrets and
  private keys anywhere in a response

The client is read-oriented and returns the controller's JSON (`dict` /
`list`) as is. Call any endpoint with `get()`, `post()` or `get_paged()`, or
subclass `OmadaOpenApiClient` to add your own `get_*` methods.

## Install

```bash
pip install "omada-openapi @ git+https://github.com/t3knoid/omada-openapi@v0.1.0"
```

Requires Python 3.10+. Dependencies: `requests`, `urllib3`.

## Quick start

```python
from omada_openapi import (
    OmadaOpenApiClient,
    discover_controller_id,
    openapi_discover_site,
    openapi_login,
)

base_url = "https://192.168.1.10:8043"
omadac_id = discover_controller_id(base_url, verify_ssl=False)

login = openapi_login(
    base_url, omadac_id, "<client-id>", "<client-secret>", verify_ssl=False,
)
site_id, site_name = openapi_discover_site(
    login.base_url, omadac_id, login.session, site_name="Home",
)

client = OmadaOpenApiClient(
    login.base_url, omadac_id, login.access_token,
    session=login.session,
)

devices = client.get_devices(site_id)
leases = client.get_dhcp_leases(site_id)
jumbo = client.get(f"sites/{site_id}/jumbo")
port_forwards = client.get_paged(f"sites/{site_id}/nat/port-forwardings")
```

For **Authorization Code Mode**, use `openapi_auth_code_login(base_url,
omadac_id, client_id, client_secret, username, password)` instead of
`openapi_login`; it returns the same `OpenApiLoginResult`.

Paths are relative to `/openapi/v1/{omadacId}/`. Pass `api_version="v2"` for
the endpoints that live under `/openapi/v2/`.

## API

| Name | Description |
| --- | --- |
| `discover_controller_id(base_url)` | Read `omadacId` from `GET /api/info` (no auth) |
| `openapi_login(...)` | Client Credentials Mode; returns `OpenApiLoginResult(access_token, session, base_url)` |
| `openapi_auth_code_login(...)` | Authorization Code Mode; same result |
| `openapi_discover_site(...)` | Return `(site_id, site_name)`; matches `site_name` case-insensitively, or auto-selects the only site |
| `OmadaOpenApiClient.get(path, params=None)` | GET and return the `result` payload |
| `OmadaOpenApiClient.post(path, payload)` | POST a query body and return the `result` payload |
| `OmadaOpenApiClient.get_paged(path)` | Fetch every page into one list |
| `OmadaOpenApiClient.get_devices(site_id)` | Adopted devices |
| `OmadaOpenApiClient.get_networks(site_id)` | LAN networks |
| `OmadaOpenApiClient.get_dhcp_leases(site_id)` | Current DHCP leases |
| `OmadaOpenApiClient.redact(data)` | Mask credentials unless `include_secrets` is set |
| `redact_secrets(data)` / `contains_secrets(data)` | Standalone redaction helpers |
| `normalize_mac(mac)` | `aa:bb:…` → `AA-BB-…` for comparisons |
| `OmadaAPIError` | Raised when the controller returns a non-zero `errorCode`; has `.error_code` |

## Configuration

| Setting | Default | Description |
| --- | --- | --- |
| `request_interval` (or `OMADA_REQUEST_INTERVAL`) | `0.2` s | Minimum gap between calls; doubles (up to 2 s) after a rate-limit answer |
| `timeout` | `30` s | Per-request timeout |
| `verify_ssl` | `True` | Set `False` for a self-signed controller certificate (a warning is emitted) |

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
flake8 . --max-line-length=120
```

## Projects using it

- [omada_network](https://github.com/t3knoid/omada_network) — exports an
  Omada site's configuration to YAML and Markdown documentation

## License

MIT. See [LICENSE](LICENSE).
