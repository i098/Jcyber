# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportPrivateUsage=false
"""MCP tool-level tests: exercise every management tool function through the
server state + fakes. Each tool is called directly (not via MCP transport)
so we test business logic and annotations without needing live backends."""

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import jcyber.mcp_server as _mod
from jcyber.mcp_server import (
    _state,
    commit_learnings,
    confirm_difference,
    create_attack_chain,
    create_hypothesis,
    get_attack_chains,
    get_decision_trace,
    get_state,
    intake_target,
    mcp,
    next_chain_step,
    promote_finding,
    recall_lessons,
    record_retest,
    render_findings_report,
    retest_finding,
    retire_hypothesis,
    score_finding,
    search_evidence,
)
from jcyber.types import Evidence, Scope, ScopeItem
from tests.fakes import FakeGraph, FakeHands, FakeMemory

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset server state before each test."""
    old_graph = _state.graph
    old_hands = _state.hands
    old_memory = _state.memory
    old_cfg = _state.cfg
    old_scope = _state.scope
    old_eid = _state.engagement_id
    old_e = _state._ev_seq
    old_h = _state._h_seq
    old_f = _state._f_seq
    old_bc = _mod._backends_initialized

    yield

    _state.graph = old_graph
    _state.hands = old_hands
    _state.memory = old_memory
    _state.cfg = old_cfg
    _state.scope = old_scope
    _state.engagement_id = old_eid
    _state._ev_seq = old_e
    _state._h_seq = old_h
    _state._f_seq = old_f
    _mod._backends_initialized = old_bc


def _wire_fakes(
    graph: FakeGraph | None = None,
    hands: FakeHands | None = None,
    memory: FakeMemory | None = None,
) -> None:
    # Prevent _ensure_backends from trying real connections
    _mod._backends_initialized = True
    _state.graph = graph or FakeGraph()  # type: ignore[assignment]
    _state.hands = hands or FakeHands()  # type: ignore[assignment]
    _state.memory = memory or FakeMemory()  # type: ignore[assignment]
    _state.engagement_id = "test-eng"
    _state._ev_seq = 0
    _state._h_seq = 0
    _state._f_seq = 0
    _state._ac_seq = 0


def test_guidance_errors_reach_the_agent():
    """Anticipated failures keep their message through the MCP boundary.
    The lib wraps non-ToolError exceptions as a bare "Error executing tool
    get_state" — the agent then can't tell intake from Memgraph from scope."""
    # No intake yet: engagement/scope/hands all unset, backends not ensured.
    _state.engagement_id = ""
    _state.scope = None
    _state.graph = None
    _mod._backends_initialized = False
    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    ctx = cast("Any", None)  # tools use module state, never the MCP context
    with pytest.raises(ToolError, match="No engagement loaded. Call intake_target first."):
        asyncio.run(tools["get_state"].run({}, context=ctx))
    with pytest.raises(ToolError, match="No engagement loaded. Call intake_target first."):
        asyncio.run(
            tools["promote_finding"].run({"hypothesis_id": "H-001", "title": "t"}, context=ctx)
        )


# ---------------------------------------------------------------------------
# Annotation tests — every tool has all four hints set to explicit booleans
# ---------------------------------------------------------------------------


def test_all_tools_have_annotations():
    """Every registered tool has readOnlyHint, destructiveHint,
    idempotentHint, and openWorldHint set to explicit booleans."""
    tools = mcp._tool_manager.list_tools()
    assert len(tools) > 0, "no tools registered"
    for tool in tools:
        ann = tool.annotations
        assert ann is not None, f"{tool.name}: missing annotations"
        assert isinstance(ann.read_only_hint, bool), f"{tool.name}: readOnlyHint not bool"
        assert isinstance(ann.destructive_hint, bool), f"{tool.name}: destructiveHint not bool"
        assert isinstance(ann.idempotent_hint, bool), f"{tool.name}: idempotentHint not bool"
        assert isinstance(ann.open_world_hint, bool), f"{tool.name}: openWorldHint not bool"


def test_dispatchers_cover_all_categories():
    """One dispatcher per HexStrike category, exploit-bearing ones destructive."""
    from jcyber.clients.hexstrike import HEXSTRIKE_CATEGORIES
    from jcyber.mcp_server import EXPLOIT_TOOLS

    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    for cat, members in HEXSTRIKE_CATEGORIES.items():
        name = f"scan_{cat}"
        assert name in tools, f"dispatcher {name} not registered"
        ann = tools[name].annotations
        assert ann is not None
        wants = any(m in EXPLOIT_TOOLS for m in members)
        assert ann.destructive_hint is wants, f"{name}: destructive={ann.destructive_hint}"


def test_dispatcher_runs_member_and_captures_evidence():
    """scan_essential routes a raw HexStrike tool name through the evidence
    path — no operator confirmation gate, straight execution."""
    hands = FakeHands()
    _wire_fakes(hands=hands)
    _set_scope()
    tool = mcp._tool_manager.get_tool("scan_essential")
    assert tool is not None
    result = json.loads(
        asyncio.run(tool.run({"tool": "nmap", "target": _IN_SCOPE_URL}, context=cast("Any", None)))
    )
    assert result["status"] == "success"
    assert hands.calls[0] == ("nmap", {"target": _IN_SCOPE_URL})


def test_dispatcher_unknown_member_lists_members():
    _wire_fakes()
    _set_scope()
    tool = mcp._tool_manager.get_tool("scan_essential")
    assert tool is not None
    with pytest.raises(ToolError, match="Members:"):
        asyncio.run(
            tool.run({"tool": "not_a_tool", "target": _IN_SCOPE_URL}, context=cast("Any", None))
        )


def test_dispatcher_scope_gates():
    _wire_fakes()
    _set_scope()
    tool = mcp._tool_manager.get_tool("scan_osint")
    assert tool is not None
    with pytest.raises(ToolError, match="out of scope"):
        asyncio.run(
            tool.run(
                {"tool": "subfinder", "target": "https://evil.example/"}, context=cast("Any", None)
            )
        )


def test_readonly_tools_not_destructive():
    """Read-only tools must not also be destructive."""
    for tool in mcp._tool_manager.list_tools():
        if tool.annotations and tool.annotations.read_only_hint:
            assert not tool.annotations.destructive_hint, (
                f"{tool.name}: read-only but also destructive"
            )


# ---------------------------------------------------------------------------
# Management tools — each tool referenced by name, exercised through fakes
# ---------------------------------------------------------------------------


def test_get_state():
    _wire_fakes()
    result = json.loads(get_state())
    assert "phase" in result


def test_get_state_includes_coverage():
    """get_state carries the coverage gap signal when scope is loaded."""
    graph = FakeGraph()
    graph.evidence.append(
        Evidence(
            engagement_id="test-eng",
            id="E-001",
            tool="httpx_probe",
            target="https://example.com/",
            ts="2026-10-10T00:00:00Z",
            summary="alive",
            sha256="0" * 64,
            raw_path="/tmp/e1.json",
        )
    )
    _wire_fakes(graph=graph)
    _set_scope()
    result = json.loads(get_state())
    assert result["coverage"]["in_scope_count"] == 1
    assert result["coverage"]["covered"] == ["example.com"]
    assert result["coverage"]["uncovered"] == []
    assert result["assets"] == []


def test_execute_capture_builds_asset_chain():
    """Every scan derives host/service/endpoint assets and links evidence to
    the leaf — the endpoint-level coverage the planner gap-fills on."""
    hands = FakeHands()
    graph = FakeGraph()
    _wire_fakes(hands=hands, graph=graph)
    _set_scope()
    result = _mod._execute_capture("scan_essential", "https://example.com:8443/admin", {})
    assert result["status"] == "success"
    values = [a["value"] for a in graph.asset_coverage("test-eng")]
    assert values == ["example.com", "example.com:8443", "example.com:8443/admin"]
    leaf = graph.asset_coverage("test-eng")[-1]
    assert leaf["evidence_count"] == 1


def test_render_findings_report():
    _wire_fakes(graph=FakeGraph(report={"engagement": "test-eng", "findings": []}))
    md = render_findings_report()
    assert "test-eng" in md


def test_get_decision_trace():
    graph = FakeGraph()
    graph.decisions = [
        {
            "ts": "t1",
            "target": "x",
            "action": "recon_active",
            "outcome": "auto",
            "next_action_conf": 0.9,
            "scope_safe": 0.9,
            "report_ready": 0.1,
            "reason": "auto",
        }
    ]
    _wire_fakes(graph=graph)
    md = get_decision_trace()
    assert "1 decision(s)" in md


def test_create_hypothesis():
    _wire_fakes()
    result = json.loads(create_hypothesis("sqli in /api/search", "E-001"))
    assert result["hypothesis_id"] == "H-001"
    assert result["evidence_id"] == "E-001"


def test_promote_finding():
    _wire_fakes()
    result = json.loads(promote_finding("H-001", "IDOR on /api/invoice"))
    assert result["finding_id"] == "F-001"
    assert result["from_hypothesis"] == "H-001"


def test_score_finding():
    _wire_fakes()
    result = json.loads(score_finding("F-001", "critical"))
    assert result["severity"] == "critical"
    assert result["status"] == "validated"


def test_score_finding_invalid_severity():
    _wire_fakes()
    with pytest.raises(ToolError, match="severity must be one of"):
        score_finding("F-001", "urgent")


def test_retire_hypothesis():
    _wire_fakes()
    result = json.loads(retire_hypothesis("H-001", "not exploitable"))
    assert result["status"] == "retired"
    assert result["reason"] == "not exploitable"


def test_create_attack_chain_demonstrated():
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "sqli", "H-001")
    graph.create_finding("test-eng", "F-002", "dump", "H-002")
    _wire_fakes(graph=graph)
    result = json.loads(
        create_attack_chain("Debug param to DB dump", "Full database access", ["F-001", "F-002"])
    )
    assert result["chain_id"] == "AC-001"
    assert result["status"] == "demonstrated"
    assert result["steps"] == ["F-001", "F-002"]


def test_create_attack_chain_theoretical():
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "sqli", "H-001")
    graph.hypothesis_ids.add("H-002")
    _wire_fakes(graph=graph)
    result = json.loads(
        create_attack_chain("Possible chain", "Needs validation", ["F-001", "H-002"])
    )
    assert result["status"] == "theoretical"


def test_create_attack_chain_empty_steps():
    _wire_fakes()
    with pytest.raises(ToolError, match="at least one step"):
        create_attack_chain("empty", "none", [])


def test_create_attack_chain_rejects_unrepresentable_steps():
    """ARTEX lineage enforcement: a step referencing no finding/hypothesis
    node is rejected at create time, never silently dropped."""
    _wire_fakes()
    with pytest.raises(ToolError, match=r"F-404.*produce the evidence"):
        create_attack_chain("Ghost chain", "vaporware", ["F-404"])


def test_get_attack_chains_empty():
    _wire_fakes()
    result = json.loads(get_attack_chains())
    assert result == {"chains": []}


def test_next_chain_step_frontier():
    """Frontier = first unscored step; earlier steps being validated gates it."""
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "sqli", "H-001")
    graph.create_finding("test-eng", "F-002", "dump", "H-002")
    _wire_fakes(graph=graph)
    create_attack_chain("Chain", "impact", ["F-001", "F-002"])
    result = json.loads(next_chain_step("AC-001"))
    assert result["next_step"] == "F-001"
    assert result["state"] == "frontier"
    # score F-001 -> frontier advances to F-002
    score_finding("F-001", "high", "confirmed")
    result = json.loads(next_chain_step("AC-001"))
    assert result["next_step"] == "F-002"
    # score F-002 -> chain complete
    score_finding("F-002", "critical", "dumped")
    result = json.loads(next_chain_step("AC-001"))
    assert result["state"] == "complete"


def test_next_chain_step_unknown_chain():
    _wire_fakes()
    with pytest.raises(ToolError, match="no attack chain"):
        next_chain_step("AC-999")


def test_search_evidence_greps_raw_files(tmp_path):
    """Trace exchange: raw tool output stays greppable even when it never
    became a hypothesis."""
    graph = FakeGraph()
    hit = Evidence(
        engagement_id="test-eng",
        id="E-001",
        tool="katana_crawl",
        target="https://example.com/",
        ts="2026-10-11T00:00:00Z",
        summary="crawl",
        sha256="a" * 64,
        raw_path=str(tmp_path / "E-001.txt"),
    )
    miss = Evidence(
        engagement_id="test-eng",
        id="E-002",
        tool="nmap_scan",
        target="https://example.com/",
        ts="2026-10-11T00:00:01Z",
        summary="ports",
        sha256="b" * 64,
        raw_path=str(tmp_path / "E-002.txt"),
    )
    graph.evidence.extend([hit, miss])
    (tmp_path / "E-001.txt").write_text("found /admin endpoint with debug=1\nnoise")
    (tmp_path / "E-002.txt").write_text("22/tcp open ssh")
    _wire_fakes(graph=graph)
    result = json.loads(search_evidence("admin"))
    assert result["matches"][0]["evidence_id"] == "E-001"
    assert "debug=1" in result["matches"][0]["lines"][0]
    # miss file must not appear
    assert all(m["evidence_id"] != "E-002" for m in result["matches"])


def test_search_evidence_empty_query_rejected():
    _wire_fakes()
    with pytest.raises(ToolError, match="must not be empty"):
        search_evidence("  ")


def test_retest_finding_bundles_evidence():
    """Retest context: finding + evidence chain for targeted re-verification."""
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "IDOR on /api/users", "H-001")
    graph.findings[0]["evidence"] = [
        {"id": "E-001", "tool": "http_repeater", "summary": "swapped id"}
    ]
    _wire_fakes(graph=graph)
    result = json.loads(retest_finding("F-001"))
    assert result["id"] == "F-001"
    assert result["evidence"][0]["id"] == "E-001"


def test_retest_finding_unknown():
    _wire_fakes()
    with pytest.raises(ToolError, match="no finding"):
        retest_finding("F-999")


def test_record_retest_verdicts():
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "IDOR", "H-001")
    _wire_fakes(graph=graph)
    result = json.loads(record_retest("F-001", "reproduced", "same 200 body with swapped id"))
    assert result["verdict"] == "reproduced"
    assert graph.retests == [("F-001", "reproduced", "same 200 body with swapped id")]


def test_record_retest_rejects_bad_verdict():
    _wire_fakes()
    with pytest.raises(ToolError, match="verdict must be one of"):
        record_retest("F-001", "probably", "vibes")


def test_get_state_terminal_hint_when_exhausted():
    """Computed terminal reasoning: full coverage + nothing open = exhausted
    signal (a planning input, not a stop)."""
    graph = FakeGraph(
        projection={
            "phase": "reporting",
            "open_hypotheses": [],
            "validated_findings": ["F-001"],
            "recent_evidence": [],
            "tools_run": [],
            "unscored_findings": [],
            "attack_chains": [],
        }
    )
    graph.evidence.append(
        Evidence(
            engagement_id="test-eng",
            id="E-001",
            tool="httpx_probe",
            target="https://example.com/",
            ts="2026-10-11T00:00:00Z",
            summary="alive",
            sha256="c" * 64,
            raw_path="/tmp/e1.txt",
        )
    )
    _wire_fakes(graph=graph)
    _set_scope()
    result = json.loads(get_state())
    assert "exhausted" in result["terminal_hint"]


def test_get_state_no_terminal_hint_while_open():
    graph = FakeGraph(
        projection={
            "phase": "probing",
            "open_hypotheses": ["H-001"],
            "validated_findings": [],
            "recent_evidence": [],
            "tools_run": [],
            "unscored_findings": [],
            "attack_chains": [],
        }
    )
    _wire_fakes(graph=graph)
    _set_scope()
    result = json.loads(get_state())
    assert "terminal_hint" not in result


def test_get_attack_chains_with_data():
    graph = FakeGraph()
    graph.create_finding("test-eng", "F-001", "sqli", "H-001")
    _wire_fakes(graph=graph)
    create_attack_chain("Chain A", "Impact A", ["F-001"])
    result = json.loads(get_attack_chains())
    assert len(result) == 1
    assert result[0]["title"] == "Chain A"
    assert result[0]["status"] == "demonstrated"


def test_recall_lessons_no_memory():
    _wire_fakes()
    _state.memory = None
    result = json.loads(recall_lessons("WordPress"))
    assert result["status"] == "no_memory"


def test_recall_lessons_with_memory():
    _wire_fakes(memory=FakeMemory(priors={"lessons": ["use wpscan"]}))
    result = json.loads(recall_lessons("WordPress"))
    assert result["lessons"] == ["use wpscan"]


def test_commit_learnings_no_memory():
    _wire_fakes()
    _state.memory = None
    result = json.loads(commit_learnings())
    assert result["status"] == "no_memory"


def test_commit_learnings_with_memory():
    _wire_fakes(memory=FakeMemory())
    result = json.loads(commit_learnings())
    assert result["status"] == "committed"


# ---------------------------------------------------------------------------
# intake_target — needs _ensure_backends bypass, no graph
# ---------------------------------------------------------------------------


def test_intake_target():
    _wire_fakes()
    _state.graph = None  # skip bootstrap_engagement
    result = json.loads(intake_target("https://acme-lab.example/docs"))
    assert result["engagement_id"] == "acme-lab-example"
    assert result["target"] == "acme-lab.example"
    assert result["status"] == "active"


# ---------------------------------------------------------------------------
# Parametrized: every HexStrike tool registered with annotations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name", list(_mod.TOOL_CATALOG))
def test_hexstrike_tool_registered_with_annotations(tool_name: str) -> None:
    """Each HexStrike tool from TOOL_CATALOG is registered and annotated."""
    tool = mcp._tool_manager.get_tool(tool_name)
    assert tool is not None, f"{tool_name} not registered"
    ann = tool.annotations
    assert ann is not None, f"{tool_name}: missing annotations"
    assert isinstance(ann.read_only_hint, bool)
    assert isinstance(ann.destructive_hint, bool)
    assert isinstance(ann.idempotent_hint, bool)
    assert isinstance(ann.open_world_hint, bool)


# ---------------------------------------------------------------------------
# confirm_difference — 3-gate confirmation (absorbed from CyberStrike)
# ---------------------------------------------------------------------------


_IN_SCOPE_URL = "https://example.com/api/users/1"
_OK_200 = 'HTTP/1.1 200 OK\n\n{"user": "alice"}'


def _set_scope() -> None:
    _state.scope = Scope(
        engagement="test-eng",
        in_scope=[ScopeItem(kind="prefix", value="example.com")],
        out_of_scope=[],
        no_fuzzing_on=[],
        authorized_accounts=[],
    )


def test_confirm_difference_measurable() -> None:
    """Different bodies -> measurable_difference true, both sides as evidence."""
    hands = FakeHands(
        outputs=[
            'HTTP/1.1 200 OK\n\n{"user": "alice"}',
            'HTTP/1.1 200 OK\n\n{"user": "bob", "extra": "data"}',
        ]
    )
    _wire_fakes(hands=hands)
    _set_scope()
    result = json.loads(
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": "https://example.com/api/users/2"}),
            )
        )
    )
    assert result["status"] == "success"
    assert result["diff"]["status_match"] is True
    assert result["diff"]["body_content_match"] is False
    assert result["diff"]["measurable_difference"] is True
    assert result["baseline"]["evidence_id"] != result["attack"]["evidence_id"]
    assert hands.calls[0][0] == "http_repeater"


def test_confirm_difference_hexstrike_envelope_shape() -> None:
    """Live http-framework returns {"response": {"status_code", "content",
    "time"}} JSON — status/body/time must be read from there, not a raw
    HTTP status line."""
    hands = FakeHands(
        outputs=[
            json.dumps({"response": {"status_code": 200, "content": '{"ok": true}', "time": 0.05}}),
            json.dumps({"response": {"status_code": 403, "content": "blocked", "time": 0.02}}),
        ]
    )
    _wire_fakes(hands=hands)
    _set_scope()
    result = json.loads(
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": _IN_SCOPE_URL}),
            )
        )
    )
    assert result["diff"]["baseline_status"] == 200
    assert result["diff"]["attack_status"] == 403
    assert result["diff"]["status_match"] is False
    assert result["diff"]["measurable_difference"] is True
    assert result["diff"]["timing_delta_ms"] == -30  # 20ms - 50ms, internal timing


def test_confirm_difference_truncated_output_still_diffs() -> None:
    """Envelope outputs longer than the 4000-char output cap still diff on
    status/body — the parse happens at capture time, before truncation."""
    hands = FakeHands(
        outputs=[
            json.dumps({"response": {"status_code": 200, "content": "A" * 9000, "time": 0.1}}),
            json.dumps({"response": {"status_code": 500, "content": "B" * 9000, "time": 0.1}}),
        ]
    )
    _wire_fakes(hands=hands)
    _set_scope()
    result = json.loads(
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": _IN_SCOPE_URL}),
            )
        )
    )
    assert result["diff"]["baseline_status"] == 200
    assert result["diff"]["attack_status"] == 500
    assert result["diff"]["body_length_match"] is True  # same length, different content
    assert result["diff"]["body_content_match"] is False
    assert result["diff"]["measurable_difference"] is True


def test_confirm_difference_faster_attack_not_measurable() -> None:
    """Identical status+body with the attack FASTER (first-request warmup on
    the baseline) is NOT a finding — only a slower attack is a timing signal.
    Regression from the live swisschems trial (-775ms warmup delta)."""
    hands = FakeHands(
        outputs=[
            json.dumps({"response": {"status_code": 401, "content": "nope", "time": 1.2}}),
            json.dumps({"response": {"status_code": 401, "content": "nope", "time": 0.4}}),
        ]
    )
    _wire_fakes(hands=hands)
    _set_scope()
    result = json.loads(
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": _IN_SCOPE_URL}),
            )
        )
    )
    assert result["diff"]["timing_delta_ms"] == -800
    assert result["diff"]["measurable_difference"] is False


def test_confirm_difference_identical_not_measurable() -> None:
    """Identical responses -> NOT a finding (the false-positive rule)."""
    _wire_fakes(hands=FakeHands(output=_OK_200))
    _set_scope()
    result = json.loads(
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": _IN_SCOPE_URL}),
            )
        )
    )
    assert result["diff"]["body_content_match"] is True
    assert result["diff"]["measurable_difference"] is False
    assert abs(result["diff"]["timing_delta_ms"]) < 200


def test_confirm_difference_strip_auth() -> None:
    """strip_auth drops auth headers on that side only; others survive."""
    hands = FakeHands(output=_OK_200)
    _wire_fakes(hands=hands)
    _set_scope()
    asyncio.run(
        confirm_difference(
            json.dumps(
                {
                    "target": _IN_SCOPE_URL,
                    "params": {"headers": {"Authorization": "Bearer t", "X-Custom": "y"}},
                }
            ),
            json.dumps(
                {
                    "target": _IN_SCOPE_URL,
                    "params": {
                        "headers": {"Authorization": "Bearer t", "Cookie": "sid=1", "X-Custom": "y"}
                    },
                    "strip_auth": True,
                }
            ),
        )
    )
    assert hands.calls[0][1]["headers"] == {"Authorization": "Bearer t", "X-Custom": "y"}
    assert hands.calls[1][1]["headers"] == {"X-Custom": "y"}


def test_confirm_difference_scope_blocked() -> None:
    """Out-of-scope attack target is rejected by the scope gate."""
    _wire_fakes(hands=FakeHands(output=_OK_200))
    _set_scope()
    with pytest.raises(ToolError, match="out of scope"):
        asyncio.run(
            confirm_difference(
                json.dumps({"target": _IN_SCOPE_URL}),
                json.dumps({"target": "https://evil.com/api/users/2"}),
            )
        )


def test_confirm_difference_bad_json() -> None:
    _wire_fakes(hands=FakeHands(output=_OK_200))
    _set_scope()
    with pytest.raises(ToolError, match="must be JSON objects"):
        asyncio.run(confirm_difference("{not json", "{}"))


# ---------------------------------------------------------------------------
# promote_finding — endpoint-aware duplicate triage (absorbed from CyberStrike)
# ---------------------------------------------------------------------------


def test_promote_finding_similar_endpoint() -> None:
    """Second finding on the same endpoint surfaces the first as similar."""
    _wire_fakes()
    first = json.loads(promote_finding("H-001", "IDOR on users", _IN_SCOPE_URL))
    second = json.loads(
        promote_finding("H-002", "IDOR on users again", " HTTPS://Example.com/api/users/1 ")
    )
    assert "similar_findings" not in first
    assert second["similar_findings"][0]["id"] == "F-001"
    assert "duplicate" in second["note"]


def test_promote_finding_no_endpoint_no_shortlist() -> None:
    _wire_fakes()
    result = json.loads(promote_finding("H-001", "IDOR on users"))
    assert "similar_findings" not in result
