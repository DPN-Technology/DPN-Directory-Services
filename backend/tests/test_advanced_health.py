import json
import ssl
from unittest.mock import patch

from fastapi.testclient import TestClient

from dpn_ds.advanced_health import AdvancedHealth
from dpn_ds.app import create_app
from dpn_ds.config import Settings
from dpn_ds.directory import DemoDirectory


def cfg(**extra):
    base = {"api_token": "test", "mode": "samba", "realm": "corp.example.com",
            "controller": "dc01.corp.example.com"}
    return Settings(**{**base, **extra})


def test_disabled_is_incomplete():
    report = AdvancedHealth(cfg()).snapshot()
    assert report["summary"] == "incomplete"
    assert all(c["status"] == "not_configured" for c in report["checks"])


def test_demo_does_not_touch_network_or_secrets():
    with (
        patch("dpn_ds.advanced_health.subprocess.run") as run,
        patch("dpn_ds.advanced_health.ldap3.Connection") as bind,
        patch("dpn_ds.advanced_health.read_secret_file") as secret,
    ):
        report = AdvancedHealth(cfg(mode="demo", enable_drs=True)).snapshot()
    assert report["summary"] == "simulated"
    run.assert_not_called()
    bind.assert_not_called()
    secret.assert_not_called()


def test_ldaps_uses_verified_tls_read_only_and_no_referrals():
    with (
        patch("dpn_ds.advanced_health.read_secret_file", return_value="redacted"),
        patch("dpn_ds.advanced_health.ldap3.Tls") as tls,
        patch("dpn_ds.advanced_health.ldap3.Server") as server,
        patch("dpn_ds.advanced_health.ldap3.Connection") as conn,
    ):
        conn.return_value.bind.return_value = True
        result = AdvancedHealth(cfg(
            ldap_bind_user="svc@corp.example.com", ldap_password_file="/run/ldap",
            ldap_ca_file="/etc/ssl/certs/ad-ca.pem",
        )).ldaps_bind()
    assert result["status"] == "pass"
    assert tls.call_args.kwargs["validate"] == ssl.CERT_REQUIRED
    assert server.call_args.kwargs["use_ssl"] is True
    assert server.call_args.kwargs["port"] == 636
    assert conn.call_args.kwargs["read_only"] is True
    assert conn.call_args.kwargs["auto_referrals"] is False
    assert "redacted" not in str(result)
    conn.return_value.unbind.assert_called_once()


def test_ldaps_failed_bind_stays_failed():
    with (
        patch("dpn_ds.advanced_health.read_secret_file", return_value="secret"),
        patch("dpn_ds.advanced_health.ldap3.Connection") as conn,
    ):
        conn.return_value.bind.return_value = False
        check = AdvancedHealth(cfg(
            ldap_bind_user="svc@corp.example.com", ldap_password_file="/run/ldap"
        )).ldaps_bind()
    assert check["status"] == "fail"
    assert "secret" not in str(check)


def test_kerberos_keytab_uses_disposable_ccache_and_fixed_arguments():
    with (
        patch("dpn_ds.advanced_health.verify_keytab_file"),
        patch("dpn_ds.advanced_health.shutil.which", return_value="/usr/bin/kinit"),
        patch("dpn_ds.advanced_health.subprocess.run") as run,
    ):
        run.return_value.returncode = 0
        check = AdvancedHealth(cfg(
            krb_principal="svc@CORP.EXAMPLE.COM",
            krb_keytab_file="/run/credentials/dpn-ds.service/keytab",
        )).kerberos_keytab()
    assert check["status"] == "pass"
    arguments, opts = run.call_args
    assert arguments[0] == [
        "/usr/bin/kinit", "-k", "-t", "/run/credentials/dpn-ds.service/keytab",
        "svc@CORP.EXAMPLE.COM",
    ]
    assert opts["env"]["KRB5CCNAME"].startswith("FILE:")
    assert "KRB5_TRACE" not in opts["env"]


def test_drs_handles_failing_and_empty_neighbors():
    with (
        patch("dpn_ds.advanced_health.shutil.which", return_value="/usr/bin/samba-tool"),
        patch("dpn_ds.advanced_health.subprocess.run") as run,
    ):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"repsFrom": [
            {"consecutive failures": 0, "last attempt state": [0, "WERR_OK"]},
            {"consecutive failures": 2, "last attempt state": [5, "WERR_FAILURE"]},
        ]})
        check = AdvancedHealth(cfg(enable_drs=True)).replication()
        assert check["status"] == "fail"
        assert "1 of 2" in check["detail"]
        assert run.call_args.args[0] == [
            "/usr/bin/samba-tool", "drs", "showrepl", "--json"
        ]
        run.return_value.stdout = json.dumps({"repsFrom": []})
        assert AdvancedHealth(cfg(enable_drs=True)).replication()["status"] == "unknown"
        run.return_value.stdout = json.dumps({"repsFrom": [
            {"consecutive failures": 0, "last attempt state": [0, "WERR_OK"]},
        ]})
        assert AdvancedHealth(cfg(enable_drs=True)).replication()["status"] == "pass"


def test_advanced_api_is_authenticated_read_only():
    client = TestClient(create_app(cfg(mode="demo"), directory=DemoDirectory()))
    assert client.get("/api/v1/advanced-health").status_code == 401
    headers = {"Authorization": "Bearer test"}
    assert client.post("/api/v1/advanced-health", headers=headers).status_code == 405
    result = client.get("/api/v1/advanced-health", headers=headers)
    assert result.status_code == 200
    assert result.json()["summary"] == "simulated"
