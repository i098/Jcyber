"""Asset derivation: program-computed host -> service -> endpoint chains.
The agent never invents parentage; parsing does."""

from __future__ import annotations

from jcyber.assets import Asset, derive_assets


def test_bare_host_is_root_only() -> None:
    assert derive_assets("example.com") == [Asset("host", "example.com", None)]


def test_url_with_port_and_path_full_chain() -> None:
    assets = derive_assets("https://api.example.com:8443/admin/users")
    assert [a.kind for a in assets] == ["host", "service", "endpoint"]
    assert assets[0].value == "api.example.com"
    assert assets[1].value == "api.example.com:8443"
    assert assets[1].parent == "api.example.com"
    assert assets[2].value == "api.example.com:8443/admin/users"
    assert assets[2].parent == "api.example.com:8443"


def test_path_without_port_attaches_to_host() -> None:
    assets = derive_assets("http://example.com/api/users")
    assert [a.kind for a in assets] == ["host", "endpoint"]
    assert assets[1].parent == "example.com"
    assert assets[1].value == "example.com/api/users"


def test_trailing_slash_and_root_paths_dont_create_endpoints() -> None:
    assert derive_assets("https://example.com/") == [Asset("host", "example.com", None)]
    assert derive_assets("https://example.com") == [Asset("host", "example.com", None)]


def test_empty_target_no_assets() -> None:
    assert derive_assets("") == []
