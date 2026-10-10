"""Jcyber MCP server — exposes pentesting tools to an agent harness.

The harness (Claude Code, or any MCP-capable agent) is the reasoning loop.
Jcyber provides scope-gated tools, graph state, memory, and engagement
management. Safety is enforced in code: the scope gate runs before every
HexStrike call, exploit actions require operator confirmation, and all
evidence is normalized into the engagement graph.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import time
from typing import Any, cast

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from .clients.caido import CaidoProxy
from .clients.hexstrike import HexStrikeHands
from .clients.memgraph import MemgraphStore
from .clients.tencentdb import TencentMemory
from .clients.toon import CliToonCodec
from .config import Engagement
from .intake import default_engagement_json, intake_link
from .learn import distill
from .normalize import normalize
from .report import render as render_report
from .scope import coverage, in_scope, violates_no_fuzzing
from .trace import render as render_trace
from .types import Scope

# ---------------------------------------------------------------------------
# Tool catalog: every HexStrike tool the agent can call, with a description
# the agent sees when listing tools. Grouped by phase.
# ---------------------------------------------------------------------------

TOOL_CATALOG: dict[str, str] = {
    # recon — passive
    "subfinder_scan": "Passive subdomain enumeration via multiple sources",
    "amass_scan": "In-depth subdomain enumeration and mapping",
    "gau_discovery": "Fetch known URLs from AlienVault, Wayback, Common Crawl",
    "waybackurls_discovery": "Fetch URLs from the Wayback Machine archive",
    "paramspider_discovery": "Mine parameters from web archives for a domain",
    "httpx_probe": "HTTP probe: live hosts, status codes, tech fingerprint, titles",
    "wafw00f_scan": "Detect web application firewalls",
    # recon — active
    "nmap_scan": "Port scan and service/version detection (TCP/UDP)",
    "rustscan_fast_scan": "Fast port scanner (Rust-based), feeds results to nmap",
    "masscan_high_speed": "High-speed port scanner for large ranges",
    "nikto_scan": "Web server vulnerability scanner (CGI, misconfig, headers)",
    "katana_crawl": "Fast web crawler for endpoint and parameter discovery",
    "hakrawler_crawl": "Simple fast web crawler for link and endpoint discovery",
    "gobuster_scan": "Directory/file/DNS/vhost brute-force",
    "dirb_scan": "Web content scanner (directory brute-force)",
    "ffuf_scan": "Web fuzzer — directories, parameters, vhosts, custom positions",
    "feroxbuster_scan": "Recursive content discovery (Rust-based web fuzzer)",
    "http_framework_test": "HTTP method and framework detection",
    # probing
    "nuclei_scan": "Template-based vulnerability scanner (9000+ templates)",
    "sqlmap_scan": "SQL injection detection and exploitation",
    "wpscan_analyze": "WordPress vulnerability scanner",
    "dalfox_xss_scan": "XSS vulnerability scanner and parameter analysis",
    "xsser_scan": "Cross-site scripting detection framework",
    "jaeles_vulnerability_scan": "Customizable vulnerability scanner",
    "jwt_analyzer": "JWT token analysis (signature, claims, known weaknesses)",
    "api_fuzzer": "API endpoint fuzzing (REST, GraphQL)",
    "graphql_scanner": "GraphQL introspection, injection, and DoS testing",
    "comprehensive_api_audit": "Full API security audit (auth, IDOR, injection, rate-limit)",
    "arjun_scan": "HTTP parameter discovery",
    "qsreplace": "Query string parameter replacement for testing",
    "http_repeater": "Replay and modify HTTP requests (like Burp Repeater)",
    "browser_agent_inspect": "Browser-based inspection (JS-rendered content, DOM)",
    "netexec_scan": "Network service enumeration (SMB, LDAP, WinRM, etc.)",
    "smbmap_scan": "SMB share enumeration and access testing",
    "enum4linux_scan": "Windows/Samba enumeration (users, shares, policies)",
    # fuzzing
    "wfuzz_scan": "Web fuzzer for parameters, headers, and paths",
    # verify
    # (http_repeater, browser_agent_inspect, nuclei_scan already listed)
    # exploit (require operator confirmation)
    "metasploit_run": "Metasploit module execution (REQUIRES OPERATOR CONFIRMATION)",
    "pwntools_exploit": "Custom exploit via pwntools (REQUIRES OPERATOR CONFIRMATION)",
    "hydra_attack": "Network login brute-force (REQUIRES OPERATOR CONFIRMATION)",
    "hashcat_crack": "Password hash cracking (REQUIRES OPERATOR CONFIRMATION)",
    "john_crack": "John the Ripper hash cracking (REQUIRES OPERATOR CONFIRMATION)",
    "responder_credential_harvest": (
        "LLMNR/NBT-NS credential harvesting (REQUIRES OPERATOR CONFIRMATION)"
    ),
}

# Exploit tools — require explicit operator confirmation before execution
EXPLOIT_TOOLS = frozenset(
    {
        "metasploit_run",
        "pwntools_exploit",
        "hydra_attack",
        "hashcat_crack",
        "john_crack",
        "responder_credential_harvest",
    }
)

# Fuzzing tools — blocked on paths in no_fuzzing_on
FUZZING_TOOLS = frozenset({"ffuf_scan", "wfuzz_scan", "api_fuzzer", "jaeles_vulnerability_scan"})


# ---------------------------------------------------------------------------
# Server state — initialized at startup, shared across all tool calls
# ---------------------------------------------------------------------------


class ServerState:
    """Mutable runtime state for the MCP server. Initialized from env vars
    and engagement directory at startup."""

    def __init__(self) -> None:
        self.hands: HexStrikeHands | None = None
        self.graph: MemgraphStore | None = None
        self.memory: TencentMemory | None = None
        self.caido: CaidoProxy | None = None
        self.cfg: Engagement | None = None
        self.scope: Scope | None = None
        self.engagement_id: str = ""
        self._ev_seq: int = 0
        self._h_seq: int = 0
        self._f_seq: int = 0
        self._ac_seq: int = 0

    def next_evidence_id(self) -> str:
        self._ev_seq += 1
        return f"E-{self._ev_seq:03d}"

    def next_hypothesis_id(self) -> str:
        self._h_seq += 1
        return f"H-{self._h_seq:03d}"

    def next_finding_id(self) -> str:
        self._f_seq += 1
        return f"F-{self._f_seq:03d}"

    def next_chain_id(self) -> str:
        self._ac_seq += 1
        return f"AC-{self._ac_seq:03d}"


_state = ServerState()


def get_server_state() -> ServerState:
    """Public accessor for the server state singleton."""
    return _state


def _require_engagement() -> None:
    if not _state.engagement_id:
        raise ToolError("No engagement loaded. Call intake_target first.")


def _require_graph() -> MemgraphStore:
    _ensure_backends()
    _require_engagement()
    if _state.graph is None:
        raise ToolError("Memgraph not connected. Set MEMGRAPH_URI env var.")
    return _state.graph


def _require_hands() -> HexStrikeHands:
    _ensure_backends()
    if _state.hands is None:
        raise ToolError("HexStrike not connected. Set HEXSTRIKE_URL env var.")
    return _state.hands


def _require_scope() -> Scope:
    if _state.scope is None:
        raise ToolError("No scope loaded. Call intake_target first.")
    return _state.scope


def _check_scope(target: str) -> None:
    """Deterministic scope gate — runs before every HexStrike call.
    String matching against scope.toon, no model, non-jailbreakable."""
    scope = _require_scope()
    if not in_scope(target, scope):
        raise ToolError(
            f"BLOCKED: target {target!r} is out of scope. "
            f"In-scope: {[i.value for i in scope.in_scope]}. "
            f"Out-of-scope: {[o.value for o in scope.out_of_scope]}."
        )


def _check_fuzzing(target: str) -> None:
    scope = _require_scope()
    if violates_no_fuzzing(target, scope):
        raise ToolError(
            f"BLOCKED: fuzzing on {target!r} violates no_fuzzing_on constraint. "
            f"Protected paths: {list(scope.no_fuzzing_on)}"
        )


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = MCPServer(
    "jcyber",
    instructions=(
        "Jcyber pentesting toolkit. Use intake_target to start an engagement, "
        "then use scanning/probing tools to find vulnerabilities. All targets "
        "are scope-checked before execution. Create hypotheses from evidence, "
        "promote to findings when confirmed. Use get_state to see engagement "
        "progress. Use render_report when done."
    ),
)


# ---------------------------------------------------------------------------
# Engagement management tools
# ---------------------------------------------------------------------------


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    )
)
def intake_target(
    url: str,
    severity: str = "critical",
) -> str:
    """Create a new engagement from a target URL. Sets up scope (apex domain +
    subdomains), initializes the graph, and returns the engagement ID.

    severity: minimum finding severity to report (critical, high, medium, low, none).
    """
    _ensure_backends()
    try:
        result = intake_link(url, severity)
    except ValueError as e:
        # intake raises ValueError for CLI humans; the agent needs the text.
        raise ToolError(f"intake failed: {e}") from e
    _state.engagement_id = result.slug
    CliToonCodec()

    # Build scope
    from .config import scope_from_json

    _state.scope = scope_from_json(result.scope_json)

    # Build engagement config
    eng_json = default_engagement_json(result.host, result.slug)
    _state.cfg = Engagement.from_json(eng_json)

    # Bootstrap Memgraph if connected
    if _state.graph is not None:
        scope_items = []
        raw_scope = result.scope_json
        if isinstance(raw_scope, dict):
            in_s = raw_scope.get("in_scope")
            if isinstance(in_s, list):
                scope_items: list[dict[str, str]] = [
                    {"kind": str(i.get("kind", "host")), "value": str(i.get("value", ""))}
                    for i in in_s
                    if isinstance(i, dict)
                ]
        _state.graph.bootstrap_engagement(result.slug, result.host, scope_items)

    return json.dumps(
        {
            "engagement_id": result.slug,
            "target": result.host,
            "scope": {
                "in_scope": [f"{i.kind}:{i.value}" for i in _state.scope.in_scope],
                "out_of_scope": [f"{i.kind}:{i.value}" for i in _state.scope.out_of_scope],
            },
            "severity_focus": severity,
            "status": "active",
        },
        indent=2,
    )


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def get_state() -> str:
    """Get the current engagement state: phase, open hypotheses, recent
    evidence, validated findings, tools already run, and which in-scope
    targets are still untested. Call this to decide what to do next."""
    graph = _require_graph()
    state = graph.project_state(_state.engagement_id)
    if isinstance(state, dict) and _state.scope is not None:
        # Coverage: the planner's 'what is untested' signal (ARTEX-style).
        targets = graph.evidence_targets(_state.engagement_id)
        state["coverage"] = coverage(_state.scope, targets)
    return json.dumps(state, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def render_findings_report() -> str:
    """Render the final report as Markdown. Only includes validated findings
    with linked evidence. Call when the engagement is complete."""
    graph = _require_graph()
    data = graph.report_data(_state.engagement_id)
    return render_report(data)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def get_decision_trace() -> str:
    """Render the decision audit trail for this engagement. Shows every action
    taken, confidence scores, and gate outcomes."""
    graph = _require_graph()
    log = graph.decision_log(_state.engagement_id)
    return render_trace(_state.engagement_id, log)


# ---------------------------------------------------------------------------
# HexStrike tools — dynamically registered, each scope-gated
# ---------------------------------------------------------------------------


def _save_evidence_raw(ev_id: str, raw: str) -> str | None:
    """Persist raw tool output to disk. Returns path on success, None on failure."""
    evidence_dir = os.path.join("evidence", "raw")
    try:
        os.makedirs(evidence_dir, exist_ok=True)
        path = os.path.join(evidence_dir, f"{ev_id}.txt")
        with open(path, "w") as f:
            f.write(raw)
        return path
    except OSError:
        return None


# Passive recon tools bypass Caido proxy routing (nothing to intercept).
_PASSIVE_TOOLS = frozenset(
    {
        "subfinder_scan",
        "amass_scan",
        "gau_discovery",
        "waybackurls_discovery",
        "paramspider_discovery",
    }
)


def _execute_capture(tool_name: str, target: str, extra: dict[str, Any]) -> dict[str, Any]:
    """Run one HexStrike call and persist it as evidence (E-###). Shared by
    every tool path — single tools and confirm_difference — so evidence
    handling has exactly one home. Returns the result dict."""
    hands = _require_hands()

    # Advisory availability check — warn but still attempt.  The /health
    # schema is guessed; a mismatch must not disable the whole toolset.
    avail = hands.is_tool_available(tool_name)
    if avail is False:
        print(
            f"[jcyber] WARNING: {tool_name!r} may not be installed in HexStrike. "
            "Attempting anyway.",
            file=sys.stderr,
        )

    call_params: dict[str, Any] = {"target": target, **extra}

    # Route through Caido proxy for active tools
    if _state.cfg and tool_name not in _PASSIVE_TOOLS:
        call_params.setdefault("proxy", _state.cfg.caido_proxy)

    started = time.monotonic()
    raw = hands.call(tool_name, call_params)
    elapsed_ms = round((time.monotonic() - started) * 1000)

    # Structured error on failure
    if raw.startswith("[tool_error]"):
        error_msg = raw[len("[tool_error] ") :]
        error_type = (
            "timeout"
            if "timed out" in error_msg
            else (
                "html_response"
                if "HTML" in error_msg
                else ("http_error" if "HTTP" in error_msg else "tool_error")
            )
        )
        return {
            "status": "error",
            "error_type": error_type,
            "tool": tool_name,
            "target": target,
            "message": error_msg,
        }

    # Always persist raw output to disk
    ev_id = _state.next_evidence_id()
    raw_path = _save_evidence_raw(ev_id, raw)

    # Auto-normalize evidence
    ev = normalize(_state.engagement_id, tool_name, target, raw, ev_id)

    # Insert into graph if connected and not a duplicate
    if _state.graph is not None and not _state.graph.seen_sha256(_state.engagement_id, ev.sha256):
        _state.graph.insert_evidence(ev)

    result: dict[str, Any] = {
        "status": "success",
        "evidence_id": ev_id,
        "tool": tool_name,
        "target": target,
        "summary": ev.summary,
        "output": raw[:4000],
        "raw_path": raw_path,
        "elapsed_ms": elapsed_ms,
    }
    # Parse the HexStrike repeater envelope BEFORE the output gets truncated
    # at 4000 chars — the diff needs the untruncated status/body/time.
    parsed = _parse_envelope(raw)
    if parsed is not None:
        result["parsed_status"] = parsed["status"]
        result["parsed_body"] = parsed["body"]
        result["parsed_time_ms"] = parsed["time_ms"]
    return result


def _make_hexstrike_tool(tool_name: str, description: str):
    """Factory: create a scope-gated MCP tool that calls HexStrike."""

    is_exploit = tool_name in EXPLOIT_TOOLS
    is_fuzzing = tool_name in FUZZING_TOOLS

    async def tool_fn(target: str, params: str = "{}") -> str:
        # Scope gate -- deterministic, non-jailbreakable
        _check_scope(target)

        if is_fuzzing:
            _check_fuzzing(target)

        if is_exploit:
            return json.dumps(
                {
                    "status": "CONFIRMATION_REQUIRED",
                    "tool": tool_name,
                    "target": target,
                    "message": (
                        f"Exploit tool {tool_name!r} requires explicit operator confirmation. "
                        "This is a safety constraint that cannot be bypassed. "
                        "Ask the operator to confirm before proceeding."
                    ),
                }
            )

        extra: dict[str, Any] = json.loads(params) if params and params != "{}" else {}
        return json.dumps(_execute_capture(tool_name, target, extra))

    # Set proper name and docstring for MCP registration
    tool_fn.__name__ = tool_name
    tool_fn.__doc__ = (
        f"{description}\n\n"
        f"target: the host, URL, or IP to scan (must be in scope).\n"
        f"params: JSON object of additional tool-specific parameters (optional)."
    )
    return tool_fn


# Register all HexStrike tools with annotations
for _name, _desc in TOOL_CATALOG.items():
    _is_exploit = _name in EXPLOIT_TOOLS
    _annotations = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=_is_exploit,
        idempotent_hint=False,
        open_world_hint=True,
    )
    mcp.add_tool(
        _make_hexstrike_tool(_name, _desc),
        name=_name,
        annotations=_annotations,
    )


# ---------------------------------------------------------------------------
# Verification — 3-gate confirmation (absorbed from CyberStrike's proxy
# sub-testers: Gate 1 baseline, Gate 2 attack, Gate 3 measurable diff)
# ---------------------------------------------------------------------------

# Auth headers stripped when strip_auth=true — CyberStrike's COMMON_AUTH_HEADERS.
AUTH_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "x-auth-token",
        "x-api-key",
        "x-access-token",
        "x-session-token",
        "x-csrf-token",
    }
)

_STATUS_LINE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})")


def _strip_auth_headers(params: dict[str, Any]) -> dict[str, Any]:
    """Remove auth headers from http_repeater params (unauthenticated replay)."""
    headers: Any = params.get("headers")
    if isinstance(headers, dict):
        typed = cast("dict[str, Any]", headers)
        params["headers"] = {k: v for k, v in typed.items() if k.lower() not in AUTH_HEADERS}
    return params


def _parse_envelope(raw: str) -> dict[str, Any] | None:
    """HexStrike http-framework JSON shape: {"response": {"status_code",
    "content", "time"}}. Returns {"status", "body", "time_ms"} or None
    when the output is not that shape."""
    try:
        obj: Any = json.loads(raw.lstrip())
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    obj_d = cast("dict[str, Any]", obj)
    resp: Any = obj_d.get("response")
    if not isinstance(resp, dict) or "status_code" not in resp:
        return None
    resp_d = cast("dict[str, Any]", resp)
    time_ms: float | None = None
    t: Any = resp_d.get("time")
    if isinstance(t, (int, float)):
        time_ms = float(t) * 1000
    return {
        "status": int(resp_d["status_code"]),
        "body": str(resp_d.get("content", "")),
        "time_ms": time_ms,
    }


def _parse_response(raw: str) -> tuple[int | None, str]:
    """Split a raw HTTP response into (status, body). Tolerant of format:
    no HTTP status line -> (None, whole text)."""
    text = raw.lstrip()
    m = _STATUS_LINE.match(text)
    if not m:
        return None, text
    _, sep, body = text.partition("\n\n")
    if not sep:
        return int(m.group(1)), ""
    return int(m.group(1)), body


def _diff_responses(baseline: dict[str, Any], attack: dict[str, Any]) -> dict[str, Any]:
    """Mechanical diff of two captured responses (absorbed from CyberStrike's
    buildDiff): exact-match booleans + timing delta. Never decides
    'vulnerable' — the agent judges the observations."""
    base_status: int | None
    atk_status: int | None
    base_t: float | None
    atk_t: float | None
    base_p: Any = baseline.get("parsed_status")
    atk_p: Any = attack.get("parsed_status")
    if base_p is not None and atk_p is not None:
        # Untruncated envelope parse done at capture time.
        base_status, base_body = int(base_p), str(baseline.get("parsed_body", ""))
        atk_status, atk_body = int(atk_p), str(attack.get("parsed_body", ""))
        bt: Any = baseline.get("parsed_time_ms")
        at: Any = attack.get("parsed_time_ms")
        base_t = float(bt) if isinstance(bt, (int, float)) else None
        atk_t = float(at) if isinstance(at, (int, float)) else None
    else:
        base_status, base_body = _parse_response(str(baseline.get("output", "")))
        atk_status, atk_body = _parse_response(str(attack.get("output", "")))
        base_t = None
        atk_t = None
    if base_t is None or atk_t is None:
        # ponytail: fall back to wall-clock (includes REST overhead) when
        # HexStrike's internal timing is absent; fine for multi-second signals.
        base_t = float(baseline.get("elapsed_ms", 0))
        atk_t = float(attack.get("elapsed_ms", 0))
    delta_ms = int(atk_t - base_t)
    status_match = base_status == atk_status
    body_match = base_body == atk_body
    return {
        "status_match": status_match,
        "baseline_status": base_status,
        "attack_status": atk_status,
        "body_length_match": len(base_body) == len(atk_body),
        "baseline_body_len": len(base_body),
        "attack_body_len": len(atk_body),
        "body_content_match": body_match,
        "timing_delta_ms": delta_ms,
        # Only a SLOWER attack counts: blind SQLi sleeps; a faster attack
        # (warm cache, first-request warmup) is noise, not a signal.
        "measurable_difference": (not status_match) or (not body_match) or delta_ms >= 200,
    }


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    )
)
async def confirm_difference(baseline_request: str, attack_request: str) -> str:
    """3-gate confirmation protocol: replay a baseline request and an attack
    request through http_repeater, then diff the responses mechanically.
    A finding requires a MEASURABLE difference (status, body, or timing) —
    "both return 200 with the same body" is NOT a finding. Both sides are
    persisted as evidence. Never decides 'vulnerable' — you judge the diff.

    baseline_request / attack_request: JSON objects:
      {"target": "https://host/path",
       "params": {http_repeater params (headers, method, body, ...)},
       "strip_auth": false}
    strip_auth drops authorization/cookie/x-*-token headers from that side —
    set it on the attack side to test unauthenticated access.
    """
    try:
        base_raw: Any = json.loads(baseline_request)
        atk_raw: Any = json.loads(attack_request)
    except ValueError as e:
        raise ToolError(f"baseline_request/attack_request must be JSON objects: {e}") from e
    if not isinstance(base_raw, dict) or not isinstance(atk_raw, dict):
        raise ToolError("baseline_request/attack_request must be JSON objects")
    base = cast("dict[str, Any]", base_raw)
    atk = cast("dict[str, Any]", atk_raw)

    captured: dict[str, dict[str, Any]] = {}
    for name, side in (("baseline", base), ("attack", atk)):
        target = str(side.get("target", ""))
        if not target:
            raise ToolError(f"{name}_request is missing 'target'")
        _check_scope(target)
        extra: dict[str, Any] = dict(side.get("params") or {})
        if side.get("strip_auth"):
            extra = _strip_auth_headers(extra)
        result = _execute_capture("http_repeater", target, extra)
        if result.get("status") != "success":
            return json.dumps({"status": "error", "side": name, **result})
        captured[name] = result

    diff = _diff_responses(captured["baseline"], captured["attack"])
    return json.dumps(
        {
            "status": "success",
            "baseline": {
                "evidence_id": captured["baseline"]["evidence_id"],
                "raw_path": captured["baseline"]["raw_path"],
            },
            "attack": {
                "evidence_id": captured["attack"]["evidence_id"],
                "raw_path": captured["attack"]["raw_path"],
            },
            "diff": diff,
            "guidance": (
                "Judge the diff: status/body difference = access-control or logic signal; "
                "timing_delta_ms >= 200 = injection signal; identical status AND body = "
                "NOT a finding. Re-run to confirm reproducibility before promote_finding."
            ),
        }
    )


# ---------------------------------------------------------------------------
# Graph tools — hypothesis/finding lifecycle
# ---------------------------------------------------------------------------


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )
)
def create_hypothesis(
    text: str,
    evidence_id: str,
) -> str:
    """Create a hypothesis (H-###) from evidence. A hypothesis is a
    testable claim about a potential vulnerability. It must reference
    specific evidence.

    text: what the hypothesis claims (e.g. "SQL injection in /api/search via q parameter")
    evidence_id: the E-### id of supporting evidence
    """
    graph = _require_graph()
    hid = _state.next_hypothesis_id()
    graph.create_hypothesis(_state.engagement_id, hid, text, evidence_id)
    return json.dumps({"hypothesis_id": hid, "text": text, "evidence_id": evidence_id})


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )
)
def promote_finding(
    hypothesis_id: str,
    title: str,
    endpoint: str = "",
) -> str:
    """Promote a confirmed hypothesis to a Finding (F-###). Only do this
    when you have strong evidence that the vulnerability is real and
    reproducible.

    hypothesis_id: the H-### id to promote
    title: descriptive title for the finding
    endpoint: affected URL or endpoint (optional). Enables duplicate detection:
      findings already recorded for the same endpoint are returned as
      similar_findings for you to triage (merge into one, or keep both if
      genuinely distinct issues).
    """
    graph = _require_graph()
    fid = _state.next_finding_id()
    # Absorbed from CyberStrike's normEndpoint: lowercase + collapse whitespace.
    dedup_key = " ".join(endpoint.lower().split())
    similar = graph.find_similar_findings(_state.engagement_id, dedup_key) if dedup_key else []
    graph.create_finding(_state.engagement_id, fid, title, hypothesis_id, endpoint, dedup_key)
    # Mark hypothesis as promoted
    graph.apply_verdict(_state.engagement_id, hypothesis_id, "promote", 1.0)
    result: dict[str, Any] = {
        "finding_id": fid,
        "title": title,
        "from_hypothesis": hypothesis_id,
    }
    if similar:
        result["similar_findings"] = similar
        result["note"] = (
            "Existing finding(s) share this endpoint. Judge whether this is a "
            "duplicate (merge into one finding) or a distinct issue before reporting."
        )
    return json.dumps(result)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def score_finding(
    finding_id: str,
    severity: str,
    justification: str = "",
) -> str:
    """Set the severity score on a finding. Severity determines whether it
    appears in the final report (based on the engagement's severity_focus).

    finding_id: the F-### id
    severity: one of: none, low, medium, high, critical
    justification: why this severity (attack impact, exploitability)
    """
    graph = _require_graph()
    sev_map = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    sev_int = sev_map.get(severity.lower())
    if sev_int is None:
        raise ToolError(f"severity must be one of {list(sev_map)}")
    graph.score_finding(_state.engagement_id, finding_id, sev_int)
    return json.dumps(
        {
            "finding_id": finding_id,
            "severity": severity,
            "justification": justification,
            "status": "validated" if sev_int >= 3 else "provisional",
        }
    )


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def retire_hypothesis(hypothesis_id: str, reason: str = "") -> str:
    """Retire a hypothesis that turned out to be false or untestable.

    hypothesis_id: the H-### id to retire
    reason: why it was retired
    """
    graph = _require_graph()
    graph.apply_verdict(_state.engagement_id, hypothesis_id, "retire", 0.0)
    return json.dumps({"hypothesis_id": hypothesis_id, "status": "retired", "reason": reason})


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )
)
def create_attack_chain(
    title: str,
    impact: str,
    step_ids: list[str],
) -> str:
    """Create an attack chain (AC-###) linking findings and hypotheses into
    an ordered exploitation path. Each step is a finding (F-###) or
    hypothesis (H-###) that the attacker moves through sequentially.

    title: descriptive name (e.g. "Debug param to DB dump via credential leak")
    impact: what the full chain achieves (e.g. "Full database access from unauthenticated position")
    step_ids: ordered list of F-### and/or H-### ids forming the chain
    """
    if not step_ids:
        raise ToolError("Attack chain requires at least one step id")
    graph = _require_graph()
    ac_id = _state.next_chain_id()
    status = graph.create_attack_chain(_state.engagement_id, ac_id, title, impact, step_ids)
    return json.dumps(
        {
            "chain_id": ac_id,
            "title": title,
            "impact": impact,
            "status": status,
            "steps": step_ids,
        }
    )


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
)
def get_attack_chains() -> str:
    """List all attack chains for the current engagement with their ordered
    steps. Use to review exploitation paths and identify gaps."""
    graph = _require_graph()
    chains = graph.get_attack_chains(_state.engagement_id)
    return json.dumps(chains, indent=2) if chains else '{"chains": []}'


# ---------------------------------------------------------------------------
# Memory tools
# ---------------------------------------------------------------------------


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    )
)
def recall_lessons(scope_description: str = "") -> str:
    """Recall lessons from long-term memory (prior engagements on similar
    targets, known techniques for this tech stack). Call early in the
    engagement to benefit from prior experience.

    scope_description: what to recall for (e.g. "WordPress 6.x, PHP, MySQL")
    """
    if _state.memory is None:
        return json.dumps({"status": "no_memory", "message": "Long-term memory not configured."})
    _require_engagement()
    priors = _state.memory.recall(
        _state.engagement_id,
        {"description": scope_description, "target": _state.cfg.target if _state.cfg else ""},
    )
    return json.dumps(priors, indent=2) if priors else '{"lessons": []}'


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    )
)
def commit_learnings() -> str:
    """Distill and commit learnings from this engagement to long-term memory.
    Call at the end of the engagement. Captures validated findings and
    retired hypotheses as durable knowledge."""
    if _state.memory is None:
        return json.dumps({"status": "no_memory", "message": "Long-term memory not configured."})
    graph = _require_graph()
    projection = graph.project_state(_state.engagement_id)
    atoms = distill(projection)
    _state.memory.commit(_state.engagement_id, atoms)
    return json.dumps({"status": "committed", "atoms": atoms}, indent=2)


# ---------------------------------------------------------------------------
# Startup / connection management
# ---------------------------------------------------------------------------


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> None:
    """Open-and-close TCP connection. Raises on refusal or timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    finally:
        sock.close()


def _parse_host_port(addr: str, default_port: int = 8889) -> tuple[str, int]:
    """Parse 'host:port' or plain 'host'. Returns (host, port)."""
    if ":" in addr:
        host, port_s = addr.rsplit(":", 1)
        return host, int(port_s)
    return addr, default_port


def _log_degraded(errors: list[str]) -> None:
    """Log missing-service warnings to stderr. Never prompts, never aborts.

    This runs inside the lazy-connect path (_ensure_backends) which fires
    during the first tool call on a LIVE MCP server. Prompting via /dev/tty
    would hang (nobody watching) and SystemExit would tear down the stdio
    transport, causing "transport not connected" failures on the harness side.
    """
    print("\n[jcyber] WARNING - some services unavailable:", file=sys.stderr)
    for err in errors:
        print(f"  ! {err}", file=sys.stderr)
    print("  Continuing with degraded services.\n", file=sys.stderr)


def connect_backends() -> None:
    """Connect to all backends. Delegates to _connect_missing_backends."""
    _connect_missing_backends()


def disconnect_backends() -> None:
    if _state.hands is not None:
        _state.hands.close()
    if _state.graph is not None:
        _state.graph.close()
    if _state.caido is not None:
        _state.caido.close()
    if _state.memory is not None:
        _state.memory.close()


_backends_initialized = False


def _ensure_backends() -> None:
    """Lazy backend connection — called on first tool use, not startup.

    Retries any backend that is still None on every call, so transient
    failures (service not yet started) recover without server restart.
    """
    global _backends_initialized
    if _backends_initialized and _all_backends_up():
        return
    _connect_missing_backends()
    _backends_initialized = True


def _all_backends_up() -> bool:
    """True when all network backends are connected (env-only checks excluded)."""
    return _state.hands is not None and _state.graph is not None


def _connect_missing_backends() -> None:
    """Connect only backends that are still None. Idempotent."""
    hexstrike_url = os.environ.get("HEXSTRIKE_URL", "http://127.0.0.1:8899")
    memgraph_uri = os.environ.get("MEMGRAPH_URI", "bolt://127.0.0.1:7687")
    memory_url = os.environ.get("JCYBER_MEMORY_URL")
    caido_proxy = os.environ.get("CAIDO_PROXY", "127.0.0.1:8889")
    caido_api_url = os.environ.get("CAIDO_API_URL", "http://127.0.0.1:8080")
    caido_token = os.environ.get("CAIDO_API_TOKEN")

    errors: list[str] = []

    if _state.hands is None:
        try:
            _state.hands = HexStrikeHands.connect(hexstrike_url)
            _state.hands.ping()
            print(f"[jcyber] ok HexStrike @ {hexstrike_url}", file=sys.stderr)
        except Exception as e:
            _state.hands = None
            errors.append(f"HexStrike @ {hexstrike_url}: {e}")

    if _state.graph is None:
        try:
            _state.graph = MemgraphStore.connect(memgraph_uri)
            _state.graph.ping()
            print(f"[jcyber] ok Memgraph @ {memgraph_uri}", file=sys.stderr)
        except Exception as e:
            _state.graph = None
            errors.append(f"Memgraph @ {memgraph_uri}: {e}")

    if _state.caido is None:
        try:
            host, port = _parse_host_port(caido_proxy)
            _tcp_probe(host, port)
            print(f"[jcyber] ok Caido proxy @ {caido_proxy}", file=sys.stderr)
        except Exception as e:
            errors.append(f"Caido proxy @ {caido_proxy}: {e}")

        try:
            _state.caido = CaidoProxy.connect(caido_api_url, token=caido_token)
            _state.caido.ping()
            print(f"[jcyber] ok Caido API @ {caido_api_url}", file=sys.stderr)
        except Exception as e:
            _state.caido = None
            errors.append(f"Caido API @ {caido_api_url}: {e}")

    if _state.memory is None:
        if memory_url:
            try:
                _state.memory = TencentMemory.connect(memory_url)
                print(f"[jcyber] ok Memory @ {memory_url}", file=sys.stderr)
            except Exception as e:
                errors.append(f"Memory @ {memory_url}: {e}")
        elif not _backends_initialized:
            errors.append("JCYBER_MEMORY_URL not set")

    if errors:
        _log_degraded(errors)


def run_server() -> None:
    """Start the MCP server (stdio transport)."""
    from dotenv import load_dotenv

    load_dotenv()  # .env secrets into os.environ BEFORE backend checks
    # ponytail: don't call connect_backends() here — it blocks 2+ seconds
    # and prevents MCP initialize from responding within OMP's timeout.
    # Backends connect lazily on first tool call via _ensure_backends().
    try:
        mcp.run(transport="stdio")
    finally:
        disconnect_backends()
