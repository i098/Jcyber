"""Deterministic scope gate (layer 1). No model, non-jailbreakable string
matching against scope.toon. Out-of-scope always wins. This layer can never
be argued around (AGENTS.md invariant #2).

Matching is deliberately conservative: paths are lowercased and matched on
segment boundaries, so a 'Do Not Test' carve-out for /pay/ also blocks /pay,
/PAY, and /pay/anything -- but not a distinct sibling like /payments."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from .types import Scope, ScopeItem


def _parse(target: str) -> tuple[str, str]:
    """Return (host, path), both lowercased, for a URL, host, or host/path."""
    u = urlsplit(target if "://" in target else "http://" + target)
    return (u.hostname or "").lower(), (u.path or "").lower()


def _under(subject: str, prefix: str) -> bool:
    """True if subject equals prefix or sits under it at a segment boundary."""
    prefix = prefix.rstrip("/")
    return subject == prefix or subject.startswith(prefix + "/")


def _matches(host: str, path: str, item: ScopeItem) -> bool:
    v = item.value.lower()
    if item.kind == "host":
        return host == v
    if item.kind == "prefix":
        base = v[2:] if v.startswith("*.") else v
        return host == base or host.endswith("." + base)
    if item.kind == "path":
        return _under(f"{host}{path}", v)
    if item.kind == "ip_range":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(item.value, strict=False)
        except ValueError:
            return False
    return False


def in_scope(target: str, scope: Scope) -> bool:
    host, path = _parse(target)
    if not host:
        return False
    if any(_matches(host, path, it) for it in scope.out_of_scope):
        return False  # out-of-scope wins on conflict
    return any(_matches(host, path, it) for it in scope.in_scope)


def violates_no_fuzzing(target: str, scope: Scope) -> bool:
    _, path = _parse(target)
    return any(_under(path, p.lower()) for p in scope.no_fuzzing_on)


def coverage(scope: Scope, evidence_targets: list[str]) -> dict[str, Any]:
    """Which in-scope items have evidence against them. Pure function of the
    evidence targets seen so far -- the planner's 'what is untested' signal."""
    hosts_paths = [_parse(t) for t in evidence_targets if _parse(t)[0]]
    covered: list[str] = []
    uncovered: list[str] = []
    for item in scope.in_scope:
        hit = any(_matches(host, path, item) for host, path in hosts_paths)
        (covered if hit else uncovered).append(item.value)
    return {
        "in_scope_count": len(scope.in_scope),
        "covered": covered,
        "uncovered": uncovered,
    }
