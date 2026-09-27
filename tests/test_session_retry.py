"""Automatic re-login when Cronometer expires the session (mocked, no network)."""

from unittest.mock import MagicMock

import pytest
import requests

from cronometer_mcp.client import CronometerClient, _is_session_expired

EXPIRED = RuntimeError(
    'GWT-RPC call failed. Response: //EX[2,1,["com.cronometer.shared.user.'
    'exceptions.NotLoggedInException/844385496","Invalid or expired session"],0,7]'
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CRONOMETER_DATA_DIR", str(tmp_path))
    c = CronometerClient(username="test@example.com", password="pw")
    c.authenticate = MagicMock()  # never touch the network
    c._parse_recent_biometrics = MagicMock(return_value=["parsed"])
    return c


def http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(f"{status} error", response=resp)


class TestDetection:
    def test_gwt_not_logged_in(self):
        assert _is_session_expired(EXPIRED)

    def test_auth_token_rejection(self):
        assert _is_session_expired(RuntimeError(
            "Session rejected while generating auth token: //EX[...Invalid or expired session"))

    @pytest.mark.parametrize("status", [401, 403])
    def test_http_auth_errors(self, status):
        assert _is_session_expired(http_error(status))

    @pytest.mark.parametrize("exc", [RuntimeError("boom"), http_error(500), ValueError("x")])
    def test_other_errors(self, exc):
        assert not _is_session_expired(exc)


class TestRetry:
    def test_relogin_then_retry_succeeds(self, client):
        client._gwt_post = MagicMock(side_effect=[EXPIRED, "//OK"])
        assert client.get_recent_biometrics() == ["parsed"]
        assert client._gwt_post.call_count == 2
        # once at the start of each attempt, once inside recovery
        assert client.authenticate.call_count == 3
        assert client._last_relogin is not None

    def test_non_session_error_is_not_retried(self, client):
        client._gwt_post = MagicMock(side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError, match="boom"):
            client.get_recent_biometrics()
        assert client._gwt_post.call_count == 1
        assert client._last_relogin is None

    def test_retries_only_once(self, client):
        client._gwt_post = MagicMock(side_effect=[EXPIRED, EXPIRED])
        with pytest.raises(RuntimeError, match="NotLoggedInException"):
            client.get_recent_biometrics()
        assert client._gwt_post.call_count == 2

    def test_cooldown_blocks_second_relogin(self, client):
        client._gwt_post = MagicMock(side_effect=[EXPIRED, "//OK", EXPIRED])
        client.get_recent_biometrics()
        auth_calls = client.authenticate.call_count
        with pytest.raises(RuntimeError, match="cooldown"):
            client.get_recent_biometrics()
        # the second call's own authenticate() ran, but no recovery login
        assert client.authenticate.call_count == auth_calls + 1

    def test_relogin_allowed_after_cooldown(self, client):
        client._relogin_cooldown = 0
        client._gwt_post = MagicMock(side_effect=[EXPIRED, "//OK", EXPIRED, "//OK"])
        client.get_recent_biometrics()
        assert client.get_recent_biometrics() == ["parsed"]
        assert client._gwt_post.call_count == 4

    def test_cooldown_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CRONOMETER_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CRONOMETER_RELOGIN_COOLDOWN", "900")
        c = CronometerClient(username="a@b.com", password="pw")
        assert c._relogin_cooldown == 900

    def test_nested_calls_relogin_once(self, client):
        # export_parsed -> export_raw: only the outer layer may retry.
        client._generate_auth_token = MagicMock(side_effect=[EXPIRED, "tok"])
        resp = MagicMock(text="Day,Metric\n2026-01-01,Weight\n")
        client.session.get = MagicMock(return_value=resp)
        rows = client.export_parsed("biometrics")
        assert rows == [{"Day": "2026-01-01", "Metric": "Weight"}]
        assert client._generate_auth_token.call_count == 2
        assert client.authenticate.call_count == 3

    def test_export_403_triggers_relogin(self, client):
        client._generate_auth_token = MagicMock(return_value="tok")
        bad = MagicMock()
        bad.raise_for_status.side_effect = http_error(403)
        good = MagicMock(text="csv")
        client.session.get = MagicMock(side_effect=[bad, good])
        assert client.export_raw("biometrics") == "csv"

    def test_write_retried_once(self, client):
        client._gwt_post = MagicMock(side_effect=[EXPIRED, "//OK[1,2]"])
        client.remove_biometric("123")
        assert client._gwt_post.call_count == 2

    def test_depth_resets_after_failure(self, client):
        client._gwt_post = MagicMock(side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            client.get_recent_biometrics()
        assert client._call_state.depth == 0


class TestResetSession:
    def test_clears_state_and_cookie_file(self, client):
        client._cookie_path.parent.mkdir(parents=True, exist_ok=True)
        client._cookie_path.write_bytes(b"x")
        client._authenticated = True
        client.nonce, client.user_id, client._diary_groups = "n", "u", []
        client.session.cookies.set("sesnonce", "n")
        client._reset_session()
        assert not client._authenticated
        assert client.nonce is None and client.user_id is None
        assert client._diary_groups is None
        assert not client._cookie_path.exists()
        assert len(client.session.cookies) == 0
