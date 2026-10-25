import pytest

from dpn_ds.config import Settings


@pytest.mark.parametrize(
    "invalid",
    ["", "https://dc01.example.com", "dc01;whoami", "a..com", "a space.com",
     "a" * 64 + ".example.com", "-invalid.example.com", "example.com/"],
)
def test_controller_rejects_unsafe_names(invalid):
    with pytest.raises(ValueError, match="DPN_DS_CONTROLLER"):
        Settings(api_token="secret", controller=invalid)


@pytest.mark.parametrize("invalid", ["", "localhost", "corp..internal", "_ldap.example.com"])
def test_realm_requires_dns_domain(invalid):
    with pytest.raises(ValueError, match="DPN_DS_REALM"):
        Settings(api_token="secret", realm=invalid)
