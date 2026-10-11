"""Memory-core tests: accumulate across engagements, dedup, cross-engagement
recall by scope target, and the real HTTP round-trip through TencentMemory."""

from __future__ import annotations

import json
import tempfile
import threading
from http.server import HTTPServer
from typing import Any

import pytest

import deploy.memory_core as mc
from deploy.memory_core import Handler
from jcyber.clients.tencentdb import TencentMemory


@pytest.fixture()
def conn() -> Any:
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        old = mc.DB_PATH
        mc.DB_PATH = f.name
        c = mc._conn()
        yield c
        c.close()
        mc.DB_PATH = old


def test_commit_accumulates_and_dedups(conn: Any) -> None:
    first = do_commit_results(conn)
    assert first == ["created", "created"]
    again = do_commit_results(conn, extra="new lesson")
    assert again == ["duplicate", "duplicate", "created"]


def do_commit_results(conn: Any, extra: str | None = None) -> list[str]:
    atoms = ["acme.example: F5 BIG-IP edge", "acme.example: IDOR on /api/users"]
    if extra:
        atoms.append(extra)
    out = mc.do_commit(conn, "eng-a", {"atoms": atoms})
    return list(out["results"])


def test_recall_hits_same_and_other_engagements(conn: Any) -> None:
    mc.do_commit(conn, "eng-a", {"atoms": ["acme-lab.example: vendor runs F5 BIG-IP"]})
    mc.do_commit(conn, "eng-b", {"atoms": ["other.example: unrelated finding"]})
    got = mc.do_recall(conn, "eng-a", {"target": "acme-lab.example", "description": ""})
    assert "F5 BIG-IP" in got["priors"]
    # NEW engagement, same target: cross-engagement recall is the point
    got = mc.do_recall(conn, "eng-fresh", {"target": "acme-lab.example", "description": ""})
    assert "F5 BIG-IP" in got["priors"]
    # unrelated target: cold start, not garbage
    got = mc.do_recall(conn, "eng-fresh", {"target": "unrelated.example", "description": ""})
    assert got["priors"] == ""


def test_recall_caps_priors(conn: Any) -> None:
    mc.do_commit(conn, "eng-a", {"atoms": [f"acme-lab.example: lesson {i}" for i in range(200)]})
    got = mc.do_recall(conn, "eng-fresh", {"target": "acme-lab.example", "description": ""})
    assert len(got["priors"]) <= mc.PRIORS_CAP + len("(priors truncated)")
    assert got["count"] < 200


def test_http_round_trip_through_adapter() -> None:
    """The seam as the orchestrator speaks it: TencentMemory -> HTTP -> core."""
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        mc.DB_PATH = f.name
        server = HTTPServer(("127.0.0.1", 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            mem = TencentMemory.connect(url)
            mem.commit("eng-a", {"atoms": ["acme-lab.example: /api/v1 IDOR, no auth on GET"]})
            priors = mem.recall("eng-fresh", {"description": "", "target": "acme-lab.example"})
            assert "IDOR" in json.dumps(priors)
            mem.close()
        finally:
            server.shutdown()
