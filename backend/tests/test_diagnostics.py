"""Unit probes are fully mocked: CI never contacts a real domain."""

import socket
from unittest.mock import patch

import dns.resolver
from fastapi.testclient import TestClient

from dpn_ds.app import create_app
from dpn_ds.config import Settings
from dpn_ds.diagnostics import DomainDiagnostics
from dpn_ds.directory import DemoDirectory


def report():
    return DomainDiagnostics("corp.example.com", "dc01.corp.example.com", "samba")


def test_demo_never_touches_network_or_clock():
    with (
        patch("dpn_ds.diagnostics.socket.create_connection") as conn,
        patch("dpn_ds.diagnostics.dns.resolver.resolve") as dns_query,
        patch("dpn_ds.diagnostics.subprocess.run") as run,
    ):
        output = DomainDiagnostics("corp.example.com", "dc01", "demo").snapshot()
    assert output["summary"] == "simulated"
    assert len(output["checks"]) == 5
    assert all(item["status"] == "simulated" for item in output["checks"])
    conn.assert_not_called()
    dns_query.assert_not_called()
    run.assert_not_called()


def test_ldap_discovery_uses_fixed_domain_record():
    query = "_ldap._tcp.dc._msdcs.corp.example.com"
    with patch("dpn_ds.diagnostics.dns.resolver.resolve", return_value=[object()]) as resolve:
        result = report()._dns("dns_ldap", "LDAP discovery", query)
    assert result["status"] == "pass"
    resolve.assert_called_once_with(query, "SRV", lifetime=1.5)


def test_dns_error_does_not_expose_exception_details():
    with patch("dpn_ds.diagnostics.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        result = report()._dns("dns_ldap", "LDAP discovery", "no-domain.example.com")
    assert result["status"] == "fail"
    assert "NXDOMAIN" not in result["detail"]


def test_port_uses_only_configured_host_and_fixed_port():
    with patch("dpn_ds.diagnostics.socket.create_connection") as connect:
        result = report()._port("tcp_kerberos", "Kerberos", 88)
    assert result["status"] == "pass"
    connect.assert_called_once_with(("dc01.corp.example.com", 88), timeout=1.5)


def test_tcp_timeout_is_sanitized():
    with patch(
        "dpn_ds.diagnostics.socket.create_connection",
        side_effect=socket.timeout("secret information"),
    ):
        result = report()._port("tcp_ldap", "LDAP", 389)
    assert result["status"] == "fail"
    assert "secret" not in result["detail"]


def test_ntp_synced_and_unsynced_results():
    with patch("dpn_ds.diagnostics.shutil.which", return_value="/usr/bin/timedatectl"):
        with patch("dpn_ds.diagnostics.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "yes\n"
            assert report()._time()["status"] == "pass"
            run.return_value.stdout = "no\n"
            assert report()._time()["status"] == "fail"
            run.assert_called_with(
                ["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                check=False, capture_output=True, text=True, timeout=1.5,
            )
    with patch("dpn_ds.diagnostics.shutil.which", return_value=None):
        assert report()._time()["status"] == "unknown"


def test_aggregate_failure_is_not_reported_healthy():
    with (
        patch.object(DomainDiagnostics, "_dns", return_value={"status": "pass"}),
        patch.object(DomainDiagnostics, "_port", return_value={"status": "fail"}),
        patch.object(DomainDiagnostics, "_time", return_value={"status": "unknown"}),
    ):
        output = report().snapshot()
    assert output["summary"] == "attention"


def test_diagnostics_api_requires_auth_and_remains_read_only():
    api = TestClient(create_app(
        Settings(api_token="test-key", mode="demo", realm="corp.example.com", controller="dc01"),
        directory=DemoDirectory(),
    ))
    assert api.get("/api/v1/diagnostics").status_code == 401
    assert api.post(
        "/api/v1/diagnostics", headers={"Authorization": "Bearer test-key"}
    ).status_code == 405
    response = api.get("/api/v1/diagnostics", headers={"Authorization": "Bearer test-key"})
    assert response.status_code == 200
    assert response.json()["summary"] == "simulated"
    assert response.json()["checks"][0]["code"] == "dns_ldap"
