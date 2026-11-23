"""Unit tests for omada_openapi.client."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from omada_openapi.client import (
    OmadaAPIError,
    OmadaOpenApiClient,
    OpenApiLoginResult,
    discover_controller_id,
    openapi_auth_code_login,
    openapi_discover_site,
    openapi_discover_site_id,
    openapi_login,
    openapi_refresh_token,
)
from omada_openapi.redaction import REDACTED


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def openapi_client() -> OmadaOpenApiClient:
    return OmadaOpenApiClient(
        base_url="https://192.168.1.1",
        omadac_id="ctrl-001",
        access_token="test-access-token",
        verify_ssl=False,
    )


def _mock_response(data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock(spec=requests.Response)
    mock.status_code = status_code
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    return mock


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestOpenApiLogin:
    def test_successful_login(self) -> None:
        token_resp = {
            "errorCode": 0,
            "msg": "Success.",
            "result": {
                "accessToken": "abc123",
                "tokenType": "Bearer",
                "expiresIn": 3600,
            },
        }
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_sess.headers = {}
            mock_session_factory.return_value = mock_sess

            result = openapi_login(
                "https://192.168.1.1",
                "ctrl-001",
                "my-client-id",
                "my-client-secret",
                verify_ssl=False,
            )

        assert isinstance(result, OpenApiLoginResult)
        assert result.access_token == "abc123"
        assert result.base_url == "https://192.168.1.1"

    def test_login_error_code(self) -> None:
        token_resp = {"errorCode": -30109, "msg": "Invalid client ID or secret."}
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "bad-id",
                    "bad-secret",
                )
        assert exc_info.value.error_code == -30109

    def test_login_missing_access_token(self) -> None:
        token_resp = {"errorCode": 0, "result": {}}
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(RuntimeError, match="no accessToken"):
                openapi_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "id",
                    "secret",
                )


class TestOpenApiAuthCodeLogin:
    def test_successful_auth_code_login(self) -> None:
        login_resp = {
            "errorCode": 0,
            "result": {"csrfToken": "csrf-123", "sessionId": "sess-abc"},
        }
        code_resp = {
            "errorCode": 0,
            "result": "OC-my-auth-code",
        }
        token_resp = {
            "errorCode": 0,
            "result": {
                "accessToken": "AT-abc123",
                "tokenType": "Bearer",
                "expiresIn": 7200,
                "refreshToken": "RT-xyz789",
            },
        }
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.side_effect = [
                _mock_response(login_resp),
                _mock_response(code_resp),
                _mock_response(token_resp),
            ]
            mock_sess.headers = {}
            mock_sess.cookies = MagicMock()
            mock_session_factory.return_value = mock_sess

            result = openapi_auth_code_login(
                "https://192.168.1.1",
                "ctrl-001",
                "my-client-id",
                "my-client-secret",
                "admin",
                "password123",
                verify_ssl=False,
            )

        assert isinstance(result, OpenApiLoginResult)
        assert result.access_token == "AT-abc123"
        assert result.base_url == "https://192.168.1.1"
        assert mock_sess.post.call_count == 3

        # Verify query params are consistent across all three steps
        step1_call = mock_sess.post.call_args_list[0]
        assert step1_call.kwargs["params"] == {
            "client_id": "my-client-id",
            "omadacId": "ctrl-001",
        }
        step2_call = mock_sess.post.call_args_list[1]
        assert step2_call.kwargs["params"] == {
            "client_id": "my-client-id",
            "omadacId": "ctrl-001",
            "response_type": "code",
        }
        step3_call = mock_sess.post.call_args_list[2]
        assert step3_call.kwargs["params"] == {
            "grant_type": "authorization_code",
            "code": "OC-my-auth-code",
        }

    def test_auth_code_login_step1_error(self) -> None:
        login_resp = {"errorCode": -30109, "msg": "Invalid credentials"}
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(login_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_auth_code_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "id",
                    "secret",
                    "admin",
                    "wrong",
                )
        assert exc_info.value.error_code == -30109


class TestDiscoverControllerId:
    def test_successful_discovery(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {"omadacId": "ctrl-discovered"},
        }
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            cid = discover_controller_id(
                "https://192.168.1.1", verify_ssl=False,
            )
        assert cid == "ctrl-discovered"

    def test_discovery_error_code(self) -> None:
        resp = {"errorCode": -1, "msg": "Unknown error"}
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError):
                discover_controller_id("https://192.168.1.1")

    def test_discovery_missing_omadac_id(self) -> None:
        resp = {"errorCode": 0, "result": {}}
        with patch("omada_openapi.client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(RuntimeError, match="omadacId"):
                discover_controller_id("https://192.168.1.1")


# ---------------------------------------------------------------------------
# Site discovery tests
# ---------------------------------------------------------------------------

class TestOpenApiDiscoverSite:
    def test_site_discovery_returns_id_and_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Home", "siteId": "site-002"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id, site_name = openapi_discover_site(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )

        assert site_id == "site-002"
        assert site_name == "Home"

    def test_single_site_auto_select(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Default", "siteId": "site-001"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )
        assert site_id == "site-001"

    def test_select_by_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [
                    {"name": "Office", "siteId": "site-001"},
                    {"name": "Home", "siteId": "site-002"},
                ],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
            site_name="Home",
        )
        assert site_id == "site-002"

    def test_name_not_found(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Office", "siteId": "site-001"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="No site named"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
                site_name="NoSuchSite",
            )

    def test_multiple_sites_no_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [
                    {"name": "Office", "siteId": "site-001"},
                    {"name": "Home", "siteId": "site-002"},
                ],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="Multiple sites"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
            )

    def test_no_sites(self) -> None:
        resp = {"errorCode": 0, "result": {"data": []}}
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="No sites found"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
            )

    def test_result_as_list(self) -> None:
        resp = {
            "errorCode": 0,
            "result": [{"name": "Default", "siteId": "site-001"}],
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )
        assert site_id == "site-001"


# ---------------------------------------------------------------------------
# URL building tests
# ---------------------------------------------------------------------------

class TestOpenApiClientUrl:
    def test_api_url_v1(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("sites/s1/acls/osg-acls")
        assert url == "https://192.168.1.1/openapi/v1/ctrl-001/sites/s1/acls/osg-acls"

    def test_api_url_v2(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("sites/s1/lan-profiles", api_version="v2")
        assert url == "https://192.168.1.1/openapi/v2/ctrl-001/sites/s1/lan-profiles"

    def test_api_url_strips_leading_slash(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("/sites/s1/foo")
        assert "//sites" not in url


# ---------------------------------------------------------------------------
# GET / pagination tests
# ---------------------------------------------------------------------------

class TestOpenApiClientGet:
    def test_get_success(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": 0, "result": [{"id": "1"}]}
            )
            result = openapi_client.get("sites/s1/profiles/groups/0")
        assert result == [{"id": "1"}]

    def test_get_raises_on_error(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": -1600, "msg": "Unsupported"}
            )
            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_client.get("sites/s1/bad/path")
        assert exc_info.value.error_code == -1600

    def test_get_paged_single_page(self, openapi_client: OmadaOpenApiClient) -> None:
        resp = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}, {"id": "2"}], "totalRows": 2},
        }
        with patch.object(
            openapi_client._session, "get", return_value=_mock_response(resp),
        ):
            items = openapi_client.get_paged("sites/s1/acls/osg-acls")
        assert len(items) == 2

    def test_get_paged_multiple_pages(self, openapi_client: OmadaOpenApiClient) -> None:
        page1 = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}], "totalRows": 2},
        }
        page2 = {
            "errorCode": 0,
            "result": {"data": [{"id": "2"}], "totalRows": 2},
        }
        with patch.object(
            openapi_client._session, "get",
            side_effect=[_mock_response(page1), _mock_response(page2)],
        ):
            items = openapi_client.get_paged(
                "sites/s1/acls/osg-acls", page_size=1,
            )
        assert len(items) == 2

    def test_get_paged_result_is_list(self, openapi_client: OmadaOpenApiClient) -> None:
        resp = {"errorCode": 0, "result": [{"id": "1"}]}
        with patch.object(
            openapi_client._session, "get", return_value=_mock_response(resp),
        ):
            items = openapi_client.get_paged("sites/s1/foo")
        assert items == [{"id": "1"}]

    def test_get_paged_stops_at_max_pages(self, openapi_client: OmadaOpenApiClient) -> None:
        infinite = {
            "errorCode": 0,
            "result": {"data": [{"id": "x"}], "totalRows": 9999},
        }
        with patch.object(
            openapi_client._session, "get",
            return_value=_mock_response(infinite),
        ):
            items = openapi_client.get_paged(
                "sites/s1/foo", page_size=1, max_pages=3,
            )
        assert len(items) == 3


class TestRateLimiting:
    """Omada answers too many requests with errorCode -7132 (or HTTP 429)."""

    _LIMITED = {"errorCode": -7132, "msg": "Our server is receiving too many requests now. Please try again later."}

    @staticmethod
    def _record_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
        """Record waits on a fake clock that sleeping moves forward."""
        sleeps: list[float] = []
        now = [1000.0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        monkeypatch.setattr("omada_openapi.client._sleep", sleep)
        monkeypatch.setattr("omada_openapi.client._monotonic", lambda: now[0])
        return sleeps

    def test_retries_rate_limited_call_with_backoff_and_slows_down(
        self, openapi_client: OmadaOpenApiClient, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        openapi_client.request_interval = 0.0
        sleeps = self._record_sleeps(monkeypatch)
        ok = _mock_response({"errorCode": 0, "result": [{"id": "1"}]})
        with (
            patch.object(openapi_client._session, "get",
                         side_effect=[_mock_response(self._LIMITED), _mock_response(self._LIMITED), ok]) as get,
            caplog.at_level(logging.WARNING, logger="omada_openapi.client"),
        ):
            assert openapi_client.get("sites/s1/devices") == [{"id": "1"}]
        assert get.call_count == 3
        assert sleeps == [2.0, 4.0]  # exponential backoff
        assert openapi_client.request_interval >= 0.5  # later calls are spaced further apart
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1  # warned once, not on every retry

    def test_http_429_honours_retry_after(
        self, openapi_client: OmadaOpenApiClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        openapi_client.request_interval = 0.0
        sleeps = self._record_sleeps(monkeypatch)
        limited = _mock_response({}, status_code=429)
        limited.headers = {"Retry-After": "7"}
        ok = _mock_response({"errorCode": 0, "result": {"ok": True}})
        with patch.object(openapi_client._session, "get", side_effect=[limited, ok]):
            assert openapi_client.get("sites/s1/x") == {"ok": True}
        assert sleeps == [7.0]
        limited.raise_for_status.assert_not_called()

    def test_gives_up_after_retries(self, openapi_client: OmadaOpenApiClient) -> None:
        from omada_openapi.client import RATE_LIMIT_RETRIES
        with patch.object(openapi_client._session, "get", return_value=_mock_response(self._LIMITED)) as get:
            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_client.get("sites/s1/x")
        assert exc_info.value.error_code == -7132
        assert get.call_count == RATE_LIMIT_RETRIES + 1
        assert "OMADA_REQUEST_INTERVAL" in str(exc_info.value)

    def test_post_queries_are_retried(self, openapi_client: OmadaOpenApiClient) -> None:
        ok = _mock_response({"errorCode": 0, "result": {"data": []}})
        with patch.object(openapi_client._session, "post", side_effect=[_mock_response(self._LIMITED), ok]) as post:
            assert openapi_client.post("sites/s1/switches/ports/select", {}) == {"data": []}
        assert post.call_count == 2

    def test_other_errors_are_not_retried(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "get",
                          return_value=_mock_response({"errorCode": -1600, "msg": "Unsupported"})) as get:
            with pytest.raises(OmadaAPIError):
                openapi_client.get("sites/s1/x")
        assert get.call_count == 1

    def test_calls_are_spaced_by_request_interval(
        self, openapi_client: OmadaOpenApiClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sleeps = self._record_sleeps(monkeypatch)
        clock = iter([100.0, 100.05, 100.2])
        monkeypatch.setattr("omada_openapi.client._monotonic", lambda: next(clock))
        openapi_client.request_interval = 0.2
        ok = _mock_response({"errorCode": 0, "result": []})
        with patch.object(openapi_client._session, "get", return_value=ok):
            openapi_client.get("a")  # first call: no wait
            openapi_client.get("b")  # 0.05s later: waits the remaining 0.15s
        assert sleeps == [pytest.approx(0.15)]

    def test_request_interval_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def make() -> OmadaOpenApiClient:
            return OmadaOpenApiClient("https://c", "id", "tok", verify_ssl=True)

        monkeypatch.delenv("OMADA_REQUEST_INTERVAL", raising=False)
        assert make().request_interval == 0.2
        monkeypatch.setenv("OMADA_REQUEST_INTERVAL", "0.5")
        assert make().request_interval == 0.5
        monkeypatch.setenv("OMADA_REQUEST_INTERVAL", "fast")
        assert make().request_interval == 0.2
        assert OmadaOpenApiClient("https://c", "id", "tok", request_interval=0).request_interval == 0

    def test_login_is_retried_when_rate_limited(self) -> None:
        ok = _mock_response({"errorCode": 0, "result": {"accessToken": "abc"}})
        with patch("omada_openapi.client._make_session") as factory:
            sess = MagicMock(spec=requests.Session)
            sess.post.side_effect = [_mock_response(self._LIMITED), ok]
            sess.headers = {}
            factory.return_value = sess
            result = openapi_login("https://c", "id", "cid", "secret")
        assert result.access_token == "abc" and sess.post.call_count == 2

    def test_site_discovery_is_retried_when_rate_limited(self) -> None:
        sites = _mock_response({"errorCode": 0, "result": {"data": [{"siteId": "s1", "name": "Office"}]}})
        sess = MagicMock(spec=requests.Session)
        sess.get.side_effect = [_mock_response(self._LIMITED), sites]
        assert openapi_discover_site("https://c", "id", sess)[0] == "s1"
        assert sess.get.call_count == 2


# ---------------------------------------------------------------------------
# Resource method tests
# ---------------------------------------------------------------------------


class TestOpenApiResourceMethods:
    def test_get_networks(self, openapi_client: OmadaOpenApiClient) -> None:
        nets = [{"name": "LAN", "vlanId": 1}]
        with patch.object(openapi_client, "get") as mock:
            mock.return_value = nets
            result = openapi_client.get_networks("site-001")
        assert result == nets

    def test_get_networks_fallback_to_paged(self, openapi_client: OmadaOpenApiClient) -> None:
        nets = [{"name": "LAN", "vlanId": 1}]
        with patch.object(openapi_client, "get") as mock_get, \
             patch.object(openapi_client, "get_paged") as mock_paged:
            mock_get.side_effect = OmadaAPIError(-1600, "Unsupported")
            mock_paged.return_value = nets
            result = openapi_client.get_networks("site-001")
        assert result == nets

    def test_get_devices(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [{"name": "Switch 1", "mac": "AA-BB-CC-DD-EE-FF"}]
        with patch.object(openapi_client, "get_paged", return_value=devices) as mock:
            result = openapi_client.get_devices("site-001")

        assert result == devices
        mock.assert_called_once_with("sites/site-001/devices")

    def test_post_returns_result_and_raises_on_error(self, openapi_client: OmadaOpenApiClient) -> None:
        ok = _mock_response({"errorCode": 0, "result": [{"mac": "AA"}]})
        with patch.object(openapi_client._session, "post", return_value=ok) as mock_post:
            assert openapi_client.post("sites/s1/switches/ports/select", {"selectAll": True}) == [{"mac": "AA"}]
        assert mock_post.call_args.kwargs["json"] == {"selectAll": True}
        bad = _mock_response({"errorCode": -1600, "msg": "Unsupported"})
        with patch.object(openapi_client._session, "post", return_value=bad):
            with pytest.raises(OmadaAPIError):
                openapi_client.post("sites/s1/switches/ports/select", {})

    def test_get_dhcp_leases(self, openapi_client: OmadaOpenApiClient) -> None:
        leases = [{"ipAddress": "192.168.2.50", "macAddress": "AA"}]
        with patch.object(openapi_client, "get_paged", return_value=leases) as mock:
            assert openapi_client.get_dhcp_leases("site-001") == leases
        mock.assert_called_once_with("sites/site-001/setting/service/dhcp/user-list")


class TestPublicApi:
    def test_redact_respects_include_secrets(self, openapi_client: OmadaOpenApiClient) -> None:
        data = {"name": "vpn", "preSharedKey": "hunter2"}
        assert openapi_client.redact(data) == {"name": "vpn", "preSharedKey": REDACTED}
        openapi_client.include_secrets = True
        assert openapi_client.redact(data) == data

    def test_package_exports(self) -> None:
        import omada_openapi

        assert omada_openapi.OmadaOpenApiClient is OmadaOpenApiClient
        assert omada_openapi.normalize_mac(" aa:bb:cc:dd:ee:ff ") == "AA-BB-CC-DD-EE-FF"
        for name in omada_openapi.__all__:
            assert hasattr(omada_openapi, name)


# ---------------------------------------------------------------------------
# Write methods
# ---------------------------------------------------------------------------

class TestWriteMethods:
    _OK = {"errorCode": 0, "msg": "Success."}

    def test_put_sends_json_body(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "put", return_value=_mock_response(self._OK)) as put:
            result = openapi_client.put("sites/s1/setting", {"name": "x"})
        assert result == self._OK
        url = put.call_args.args[0]
        assert url == "https://192.168.1.1/openapi/v1/ctrl-001/sites/s1/setting"
        assert put.call_args.kwargs["json"] == {"name": "x"}

    def test_patch_returns_result(self, openapi_client: OmadaOpenApiClient) -> None:
        resp = {"errorCode": 0, "result": {"id": "n1"}}
        with patch.object(openapi_client._session, "patch", return_value=_mock_response(resp)) as p:
            assert openapi_client.patch("sites/s1/lan-networks/n1", {"vlan": 10}) == {"id": "n1"}
        assert p.call_args.kwargs["json"] == {"vlan": 10}

    def test_delete_with_params_and_body(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "delete", return_value=_mock_response(self._OK)) as d:
            openapi_client.delete("sites/s1/things", params={"force": "true"}, payload={"ids": ["a"]})
        assert d.call_args.kwargs["params"] == {"force": "true"}
        assert d.call_args.kwargs["json"] == {"ids": ["a"]}

    def test_write_error_raises(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "put",
                          return_value=_mock_response({"errorCode": -1001, "msg": "Invalid"})):
            with pytest.raises(OmadaAPIError) as exc:
                openapi_client.put("sites/s1/setting", {})
        assert exc.value.error_code == -1001

    def test_write_is_retried_when_rate_limited(self, openapi_client: OmadaOpenApiClient) -> None:
        limited = _mock_response({"errorCode": -7132, "msg": "Too many requests"})
        with patch.object(openapi_client._session, "delete",
                          side_effect=[limited, _mock_response(self._OK)]) as d:
            openapi_client.delete("sites/s1/things/1")
        assert d.call_count == 2


# ---------------------------------------------------------------------------
# Token refresh and renewal
# ---------------------------------------------------------------------------

def _token(access: str, refresh: str = "", expires_in: int | None = 7200) -> dict:
    result: dict = {"accessToken": access, "tokenType": "bearer"}
    if refresh:
        result["refreshToken"] = refresh
    if expires_in is not None:
        result["expiresIn"] = expires_in
    return {"errorCode": 0, "msg": "Open API Get Access Token successfully.", "result": result}


_EXPIRED = {"errorCode": -44112, "msg": "The access token has expired."}


class TestRefreshToken:
    def test_login_returns_refresh_token_and_expiry(self) -> None:
        with patch("omada_openapi.client._make_session") as factory:
            sess = MagicMock(spec=requests.Session)
            sess.post.return_value = _mock_response(_token("a1", "r1", 7200))
            sess.headers = {}
            factory.return_value = sess
            result = openapi_login("https://c", "ctrl", "id", "secret")
        assert result.refresh_token == "r1"
        assert result.expires_in == 7200

    def test_refresh_posts_grant_and_updates_session(self) -> None:
        sess = MagicMock(spec=requests.Session)
        sess.headers = {}
        sess.post.return_value = _mock_response(_token("a2", "r2"))
        result = openapi_refresh_token("https://c/", "id", "secret", "r1", session=sess)
        params = sess.post.call_args.kwargs["params"]
        assert params == {"grant_type": "refresh_token", "client_id": "id",
                          "client_secret": "secret", "refresh_token": "r1"}
        assert sess.post.call_args.args[0] == "https://c/openapi/authorize/token"
        assert sess.headers["Authorization"] == "AccessToken=a2"
        assert (result.access_token, result.refresh_token) == ("a2", "r2")

    def test_refresh_keeps_old_refresh_token_when_none_returned(self) -> None:
        sess = MagicMock(spec=requests.Session)
        sess.headers = {}
        sess.post.return_value = _mock_response(_token("a2"))
        assert openapi_refresh_token("https://c", "id", "s", "r1", session=sess).refresh_token == "r1"

    def test_refresh_error_raises(self) -> None:
        sess = MagicMock(spec=requests.Session)
        sess.post.return_value = _mock_response({"errorCode": -44114, "msg": "Refresh token expired"})
        with pytest.raises(OmadaAPIError):
            openapi_refresh_token("https://c", "id", "s", "r1", session=sess)


class TestTokenRenewal:
    @pytest.fixture()
    def clock(self, monkeypatch: pytest.MonkeyPatch) -> list[float]:
        now = [1000.0]
        monkeypatch.setattr("omada_openapi.client._monotonic", lambda: now[0])
        return now

    def _client(self, **kwargs) -> OmadaOpenApiClient:  # noqa: ANN003
        defaults: dict = dict(verify_ssl=False, refresh_token="r1", client_id="id",
                              client_secret="secret", expires_in=7200)
        defaults.update(kwargs)
        return OmadaOpenApiClient("https://c", "ctrl", "a1", **defaults)

    def test_no_renewal_without_credentials(self, openapi_client: OmadaOpenApiClient) -> None:
        assert not openapi_client.can_renew_token
        with patch.object(openapi_client._session, "get", return_value=_mock_response(_EXPIRED)) as get:
            with pytest.raises(OmadaAPIError) as exc:
                openapi_client.get("sites")
        assert exc.value.error_code == -44112
        assert get.call_count == 1
        with pytest.raises(RuntimeError):
            openapi_client.renew_token()

    def test_expired_token_is_refreshed_and_call_retried(self, clock: list[float]) -> None:
        client = self._client()
        ok = _mock_response({"errorCode": 0, "result": ["site"]})
        with patch.object(client._session, "get", side_effect=[_mock_response(_EXPIRED), ok]) as get, \
                patch.object(client._session, "post", return_value=_mock_response(_token("a2", "r2"))) as post:
            assert client.get("sites") == ["site"]
        assert get.call_count == 2
        assert post.call_args.kwargs["params"]["refresh_token"] == "r1"
        assert client.access_token == "a2"
        assert client.refresh_token == "r2"
        assert client._session.headers["Authorization"] == "AccessToken=a2"

    def test_http_401_triggers_renewal(self, clock: list[float]) -> None:
        client = self._client()
        unauthorized = _mock_response({}, status_code=401)
        ok = _mock_response({"errorCode": 0, "result": {}})
        with patch.object(client._session, "put", side_effect=[unauthorized, ok]) as put, \
                patch.object(client._session, "post", return_value=_mock_response(_token("a2"))):
            client.put("sites/s1/setting", {"a": 1})
        assert put.call_count == 2

    def test_retried_only_once(self, clock: list[float]) -> None:
        client = self._client()
        with patch.object(client._session, "get", return_value=_mock_response(_EXPIRED)) as get, \
                patch.object(client._session, "post", return_value=_mock_response(_token("a2"))):
            with pytest.raises(OmadaAPIError):
                client.get("sites")
        assert get.call_count == 2

    def test_renews_before_expiry(self, clock: list[float]) -> None:
        client = self._client(expires_in=600)
        ok = _mock_response({"errorCode": 0, "result": []})
        refreshed = _mock_response(_token("a2", expires_in=600))
        with patch.object(client._session, "get", return_value=ok), \
                patch.object(client._session, "post", return_value=refreshed) as post:
            client.get("sites")
            assert post.call_count == 0
            clock[0] += 600 - 30  # inside TOKEN_RENEW_MARGIN
            client.get("sites")
            assert post.call_count == 1
            client.get("sites")
            assert post.call_count == 1  # new expiry pushed out
        assert client.access_token == "a2"

    def test_falls_back_to_relogin_when_refresh_fails(self, clock: list[float]) -> None:
        new_sess = MagicMock(spec=requests.Session)
        relogin = MagicMock(return_value=OpenApiLoginResult("a3", new_sess, "https://c", "r3", 7200))
        client = self._client(relogin=relogin)
        ok = _mock_response({"errorCode": 0, "result": []})
        refresh_failed = _mock_response({"errorCode": -44114, "msg": "Refresh token expired"})
        with patch.object(client._session, "get", side_effect=[_mock_response(_EXPIRED), ok]), \
                patch.object(client._session, "post", return_value=refresh_failed):
            client.get("sites")
        relogin.assert_called_once()
        assert (client.access_token, client.refresh_token) == ("a3", "r3")
        assert client._session.headers["Authorization"] == "AccessToken=a3"

    def test_relogin_only(self, clock: list[float]) -> None:
        relogin = MagicMock(return_value=OpenApiLoginResult("a3", MagicMock(), "https://c"))
        client = OmadaOpenApiClient("https://c", "ctrl", "a1", verify_ssl=False, relogin=relogin)
        assert client.can_renew_token
        client.renew_token()
        assert client.access_token == "a3"

    def test_connect_logs_in_and_wires_renewal(self) -> None:
        login = OpenApiLoginResult("a1", requests.Session(), "https://c", "r1", 7200)
        with patch("omada_openapi.client.discover_controller_id", return_value="ctrl") as discover, \
                patch("omada_openapi.client.openapi_login", return_value=login) as do_login:
            client = OmadaOpenApiClient.connect("https://c", "id", "secret")
        discover.assert_called_once()
        do_login.assert_called_once()
        assert client.omadac_id == "ctrl"
        assert client.access_token == "a1"
        assert client.refresh_token == "r1"
        assert client.can_renew_token
        assert client._session is login.session

    def test_connect_uses_auth_code_mode_with_user_credentials(self) -> None:
        login = OpenApiLoginResult("a1", requests.Session(), "https://c")
        with patch("omada_openapi.client.openapi_auth_code_login", return_value=login) as do_login:
            OmadaOpenApiClient.connect("https://c", "id", "secret", omadac_id="ctrl",
                                       username="u", password="p")
        assert do_login.call_args.args == ("https://c", "ctrl", "id", "secret", "u", "p")
