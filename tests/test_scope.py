"""Deterministic scope gate -- the non-jailbreakable layer 1. These are safety
tests: out-of-scope must win every conflict."""

from __future__ import annotations

from jcyber.scope import coverage, in_scope, violates_no_fuzzing
from jcyber.types import Scope


def test_in_scope_host_and_path(scope: Scope) -> None:
    assert in_scope("https://acme-lab.example/api/users/4821", scope)


def test_subdomain_prefix_in_scope(scope: Scope) -> None:
    assert in_scope("https://sub.acme-lab.example/", scope)


def test_ip_range_in_scope(scope: Scope) -> None:
    assert in_scope("http://203.0.113.5/", scope)


def test_out_of_scope_host_wins_over_prefix(scope: Scope) -> None:
    # staging.acme-lab.example matches the *.acme-lab.example prefix but is
    # explicitly out of scope -- out-of-scope must win.
    assert not in_scope("https://staging.acme-lab.example/x", scope)


def test_out_of_scope_path_wins(scope: Scope) -> None:
    assert not in_scope("https://acme-lab.example/pay/checkout", scope)


def test_unknown_host_not_in_scope(scope: Scope) -> None:
    assert not in_scope("https://evil.example/", scope)


def test_empty_target_not_in_scope(scope: Scope) -> None:
    assert not in_scope("", scope)


def test_no_fuzzing_paths(scope: Scope) -> None:
    assert violates_no_fuzzing("https://acme-lab.example/checkout/cart", scope)
    assert not violates_no_fuzzing("https://acme-lab.example/api/users", scope)


def test_out_of_scope_path_blocks_case_and_slash_variants(scope: Scope) -> None:
    # The /pay/ carve-out must hold against no-trailing-slash and case variants.
    assert not in_scope("https://acme-lab.example/pay", scope)
    assert not in_scope("https://acme-lab.example/pay/", scope)
    assert not in_scope("https://acme-lab.example/PAY/checkout", scope)


def test_sibling_path_not_over_blocked(scope: Scope) -> None:
    # /payments is a distinct segment, not covered by the /pay/ carve-out.
    assert in_scope("https://acme-lab.example/payments", scope)


def test_coverage_reports_untested(scope: Scope) -> None:
    """Coverage is the planner's gap signal: items with no evidence show
    as uncovered."""
    cov = coverage(scope, ["https://acme-lab.example/"])
    assert cov["in_scope_count"] == 4
    # apex evidence covers the host item and the *.prefix (apex == base,
    # same matching as in_scope) but not the /api/ path or the IP range
    assert cov["covered"] == ["acme-lab.example", "*.acme-lab.example"]
    assert cov["uncovered"] == ["acme-lab.example/api/", "203.0.113.0/24"]


def test_coverage_empty_evidence_all_uncovered(scope: Scope) -> None:
    cov = coverage(scope, [])
    assert cov["covered"] == []
    assert len(cov["uncovered"]) == 4


def test_coverage_staging_scan_covers_prefix_but_not_out_of_scope(scope: Scope) -> None:
    # out-of-scope items are not tracked -- only in_scope drives coverage
    cov = coverage(scope, ["https://sub.acme-lab.example/"])
    assert "*.acme-lab.example" in cov["covered"]
    assert cov["in_scope_count"] == 4
