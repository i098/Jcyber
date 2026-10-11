# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""Memgraph session-brain adapter over the Bolt driver (Memgraph is
Bolt-compatible). This is the one adapter the P1 compose smoke exercises:
`python -m jcyber.clients.memgraph --smoke`."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from neo4j import Driver, GraphDatabase

from jcyber.assets import Asset
from jcyber.types import JSON, Evidence


class MemgraphStore:
    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    @classmethod
    def connect(
        cls, uri: str = "bolt://127.0.0.1:7687", auth: tuple[str, str] | None = None
    ) -> MemgraphStore:
        return cls(GraphDatabase.driver(uri, auth=auth))

    def close(self) -> None:
        self._driver.close()

    def ping(self) -> int:
        with self._driver.session() as s:
            rec = s.run("RETURN 1 AS ok").single()
        return int(rec["ok"]) if rec is not None else 0

    def bootstrap_engagement(
        self, engagement_id: str, target: str, scope_items: list[dict[str, str]]
    ) -> None:
        """Create the Engagement node and insert scope nodes if they don't exist.
        Idempotent — safe to call on an already-bootstrapped engagement."""
        with self._driver.session() as s:
            s.run(
                "MERGE (e:Engagement {id: $eid}) "
                "SET e.target=$target, e.status='active', e.phase='recon'",
                eid=engagement_id,
                target=target,
            )
            for item in scope_items:
                s.run(
                    "MERGE (sc:Scope {engagement_id: $eid, value: $val}) "
                    "SET sc.kind=$kind, sc.in_scope=true",
                    eid=engagement_id,
                    val=item.get("value", ""),
                    kind=item.get("kind", "host"),
                )

    def project_state(self, engagement_id: str) -> JSON:
        # Core state: phase, hypotheses, validated findings
        cypher_core = (
            "MATCH (e:Engagement {id: $eid}) "
            "OPTIONAL MATCH (h:Hypothesis {engagement_id: $eid, status: 'open'}) "
            "OPTIONAL MATCH (f:Finding {engagement_id: $eid, status: 'validated'}) "
            "RETURN e.phase AS phase, collect(DISTINCT h.id) AS open_hypotheses, "
            "collect(DISTINCT f.id) AS validated_findings"
        )
        # Recent evidence: bounded to last 20 by id (cheapest ordering)
        cypher_evidence = (
            "MATCH (ev:Evidence {engagement_id: $eid}) "
            "RETURN ev.id AS id, ev.tool AS tool, ev.target AS target, ev.summary AS summary "
            "ORDER BY ev.id DESC LIMIT 20"
        )
        # Tools already run: distinct tool names from evidence
        cypher_tools = (
            "MATCH (ev:Evidence {engagement_id: $eid}) "
            "RETURN collect(DISTINCT ev.tool) AS tools_run"
        )
        # Unscored findings: need G3 severity scoring
        cypher_unscored = (
            "MATCH (f:Finding {engagement_id: $eid}) "
            "WHERE f.severity IS NULL "
            "RETURN collect(DISTINCT f.id) AS unscored_findings"
        )
        with self._driver.session() as s:
            rec = s.run(cypher_core, eid=engagement_id).single()
            ev_rows = list(s.run(cypher_evidence, eid=engagement_id))
            tools_rec = s.run(cypher_tools, eid=engagement_id).single()
            unscored_rec = s.run(cypher_unscored, eid=engagement_id).single()
        if rec is None:
            return {
                "phase": "intake",
                "open_hypotheses": [],
                "validated_findings": [],
                "recent_evidence": [],
                "tools_run": [],
                "unscored_findings": [],
                "attack_chains": [],
            }
        evidence: list[JSON] = [
            {"id": r["id"], "tool": r["tool"], "target": r["target"], "summary": r["summary"]}
            for r in ev_rows
        ]
        tools_run: list[JSON] = list(tools_rec["tools_run"]) if tools_rec else []
        unscored: list[JSON] = list(unscored_rec["unscored_findings"]) if unscored_rec else []
        chains = self.get_attack_chains(engagement_id)
        result: dict[str, JSON] = {
            "phase": rec["phase"],
            "open_hypotheses": list(rec["open_hypotheses"]),
            "validated_findings": list(rec["validated_findings"]),
            "recent_evidence": evidence,
            "tools_run": tools_run,
            "unscored_findings": unscored,
            "attack_chains": chains,
        }
        return result

    def report_data(self, engagement_id: str) -> JSON:
        cypher = (
            "MATCH (f:Finding {engagement_id: $eid, status: 'validated'}) "
            "OPTIONAL MATCH (h:Hypothesis)-[:DERIVES]->(f) "
            "OPTIONAL MATCH (h)-[:SUPPORTED_BY]->(e:Evidence) "
            "RETURN f.id AS id, f.title AS title, f.severity AS severity, "
            "f.justification AS justification, "
            "collect(DISTINCT {id: e.id, tool: e.tool, summary: e.summary}) AS evidence "
            "ORDER BY id"
        )
        with self._driver.session() as s:
            rows = list(s.run(cypher, eid=engagement_id))
        findings: list[JSON] = [
            {
                "id": r["id"],
                "title": r["title"],
                "severity": r["severity"],
                "justification": r["justification"],
                "evidence": [ev for ev in r["evidence"] if ev.get("id") is not None],
            }
            for r in rows
        ]
        chains = self.get_attack_chains(engagement_id)
        return {"engagement": engagement_id, "findings": findings, "attack_chains": chains}

    def write_decision(self, engagement_id: str, record: JSON) -> None:
        ts = record.get("ts", "") if isinstance(record, dict) else ""
        with self._driver.session() as s:
            s.run(
                "CREATE (:Decision {engagement_id: $eid, ts: $ts, payload: $payload})",
                eid=engagement_id,
                ts=ts,
                payload=json.dumps(record),
            )

    def decision_log(self, engagement_id: str) -> list[JSON]:
        with self._driver.session() as s:
            rows = list(
                s.run(
                    "MATCH (d:Decision {engagement_id: $eid}) "
                    "RETURN d.payload AS payload ORDER BY d.ts",
                    eid=engagement_id,
                )
            )
        out: list[JSON] = []
        for r in rows:
            try:
                out.append(json.loads(r["payload"]))
            except (ValueError, TypeError):
                continue
        return out

    def insert_evidence(self, ev: Evidence) -> None:
        with self._driver.session() as s:
            s.run(
                "MERGE (e:Evidence {engagement_id: $eid, id: $id}) "
                "SET e.tool=$tool, e.target=$target, e.ts=$ts, e.summary=$summary, "
                "e.sha256=$sha, e.raw_path=$path",
                eid=ev.engagement_id,
                id=ev.id,
                tool=ev.tool,
                target=ev.target,
                ts=ev.ts,
                summary=ev.summary,
                sha=ev.sha256,
                path=ev.raw_path,
            )

    def seen_sha256(self, engagement_id: str, sha256: str) -> bool:
        with self._driver.session() as s:
            rec = s.run(
                "MATCH (e:Evidence {engagement_id: $eid, sha256: $sha}) RETURN count(e) AS n",
                eid=engagement_id,
                sha=sha256,
            ).single()
        return rec is not None and int(rec["n"]) > 0

    def evidence_targets(self, engagement_id: str) -> list[str]:
        """Distinct evidence target strings -- feeds the coverage view."""
        with self._driver.session() as s:
            rec = s.run(
                "MATCH (e:Evidence {engagement_id: $eid}) "
                "RETURN collect(DISTINCT e.target) AS targets",
                eid=engagement_id,
            ).single()
        return [str(t) for t in rec["targets"]] if rec else []

    def evidence_index(self, engagement_id: str) -> list[dict[str, Any]]:
        """Id/tool/target/raw_path for every evidence row -- feeds
        search_evidence's file grep."""
        with self._driver.session() as s:
            rows = list(
                s.run(
                    "MATCH (e:Evidence {engagement_id: $eid}) "
                    "RETURN e.id AS id, e.tool AS tool, e.target AS target, "
                    "e.raw_path AS raw_path ORDER BY e.id",
                    eid=engagement_id,
                )
            )
        return [
            {"id": r["id"], "tool": r["tool"], "target": r["target"], "raw_path": r["raw_path"]}
            for r in rows
        ]

    def upsert_assets(self, engagement_id: str, assets: list[Asset]) -> None:
        """MERGE asset nodes and PARENT edges (program-computed hierarchy).
        Idempotent; values are the identity, so re-derivation is free."""
        if not assets:
            return
        with self._driver.session() as s:
            for a in assets:
                s.run(
                    "MERGE (x:Asset {engagement_id: $eid, value: $value}) "
                    "SET x.kind=$kind "
                    "WITH x "
                    "OPTIONAL MATCH (p:Asset {engagement_id: $eid, value: $parent}) "
                    "FOREACH (_ IN CASE WHEN $parent IS NULL THEN [] ELSE [1] END | "
                    "MERGE (p)-[:PARENT]->(x))",
                    eid=engagement_id,
                    value=a.value,
                    kind=a.kind,
                    parent=a.parent,
                )

    def asset_coverage(self, engagement_id: str) -> list[JSON]:
        """Per-asset evidence counts — the endpoint-level coverage view."""
        cypher = (
            "MATCH (a:Asset {engagement_id: $eid}) "
            "OPTIONAL MATCH (e:Evidence {engagement_id: $eid})-[:AGAINST]->(a) "
            "RETURN a.kind AS kind, a.value AS value, count(e) AS evidence_count "
            "ORDER BY a.value"
        )
        with self._driver.session() as s:
            rows = list(s.run(cypher, eid=engagement_id))
        return [
            {"kind": r["kind"], "value": r["value"], "evidence_count": int(r["evidence_count"])}
            for r in rows
        ]

    def link_evidence(self, engagement_id: str, evidence_id: str, asset_value: str) -> None:
        """Attach an evidence node to the asset it tested (leaf of the chain)."""
        with self._driver.session() as s:
            s.run(
                "MATCH (e:Evidence {engagement_id: $eid, id: $vid}) "
                "MATCH (a:Asset {engagement_id: $eid, value: $value}) "
                "MERGE (e)-[:AGAINST]->(a)",
                eid=engagement_id,
                vid=evidence_id,
                value=asset_value,
            )

    def apply_verdict(
        self, engagement_id: str, hypothesis_id: str, verdict: str, support: float
    ) -> None:
        with self._driver.session() as s:
            s.run(
                "MERGE (h:Hypothesis {engagement_id: $eid, id: $hid}) "
                "SET h.status=$verdict, h.support=$support",
                eid=engagement_id,
                hid=hypothesis_id,
                verdict=verdict,
                support=support,
            )

    def create_hypothesis(self, engagement_id: str, hid: str, text: str, evidence_id: str) -> None:
        with self._driver.session() as s:
            s.run(
                "MERGE (h:Hypothesis {engagement_id: $eid, id: $hid}) "
                "SET h.text=$text, h.status='open', h.support=0.5 "
                "WITH h "
                "MATCH (ev:Evidence {engagement_id: $eid, id: $evid}) "
                "MERGE (h)-[:SUPPORTED_BY]->(ev)",
                eid=engagement_id,
                hid=hid,
                text=text,
                evid=evidence_id,
            )

    def create_finding(
        self,
        engagement_id: str,
        fid: str,
        title: str,
        hypothesis_id: str,
        endpoint: str = "",
        dedup_key: str = "",
    ) -> None:
        with self._driver.session() as s:
            s.run(
                "MERGE (f:Finding {engagement_id: $eid, id: $fid}) "
                "SET f.title=$title, f.status='provisional', f.severity=null, "
                "f.endpoint=$endpoint, f.dedup_key=$dedup_key "
                "WITH f "
                "MATCH (h:Hypothesis {engagement_id: $eid, id: $hid}) "
                "MERGE (h)-[:DERIVES]->(f)",
                eid=engagement_id,
                fid=fid,
                title=title,
                hid=hypothesis_id,
                endpoint=endpoint,
                dedup_key=dedup_key,
            )

    def find_similar_findings(self, engagement_id: str, dedup_key: str) -> list[dict[str, JSON]]:
        """Findings sharing a normalized endpoint (absorbed from CyberStrike's
        findSimilar shortlist). A triage hint for the agent — never a
        dedup decision; the caller judges and merges."""
        with self._driver.session() as s:
            rows = list(
                s.run(
                    "MATCH (f:Finding {engagement_id: $eid, dedup_key: $key}) "
                    "RETURN f.id AS id, f.title AS title ORDER BY f.id LIMIT 6",
                    eid=engagement_id,
                    key=dedup_key,
                )
            )
        return [{"id": r["id"], "title": r["title"]} for r in rows]

    def score_finding(self, engagement_id: str, fid: str, severity: int) -> None:
        sev_map = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        label = sev_map.get(severity, "unknown")
        status = "validated" if severity >= 3 else "provisional"
        with self._driver.session() as s:
            s.run(
                "MATCH (f:Finding {engagement_id: $eid, id: $fid}) "
                "SET f.severity=$sev, f.status=$status",
                eid=engagement_id,
                fid=fid,
                sev=label,
                status=status,
            )

    def unscored_findings(self, engagement_id: str) -> list[str]:
        with self._driver.session() as s:
            rows = list(
                s.run(
                    "MATCH (f:Finding {engagement_id: $eid}) "
                    "WHERE f.severity IS NULL "
                    "RETURN f.id AS id",
                    eid=engagement_id,
                )
            )
        return [r["id"] for r in rows]

    def hypothesis_count(self, engagement_id: str) -> int:
        with self._driver.session() as s:
            rec = s.run(
                "MATCH (h:Hypothesis {engagement_id: $eid}) RETURN count(h) AS n",
                eid=engagement_id,
            ).single()
        return int(rec["n"]) if rec else 0

    def finding_count(self, engagement_id: str) -> int:
        with self._driver.session() as s:
            rec = s.run(
                "MATCH (f:Finding {engagement_id: $eid}) RETURN count(f) AS n",
                eid=engagement_id,
            ).single()
        return int(rec["n"]) if rec else 0

    def create_attack_chain(
        self,
        engagement_id: str,
        ac_id: str,
        title: str,
        impact: str,
        step_ids: list[str],
    ) -> str:
        """Create an AttackChain node and ordered STEP edges to findings/hypotheses.
        Returns inferred status: 'demonstrated' if all steps are Findings,
        'theoretical' if any step is a Hypothesis."""
        status = "demonstrated" if all(s.startswith("F-") for s in step_ids) else "theoretical"
        with self._driver.session() as s:
            s.run(
                "MERGE (ac:AttackChain {engagement_id: $eid, id: $acid}) "
                "SET ac.title=$title, ac.impact=$impact, ac.status=$status, "
                "ac.evidence_ids=$step_ids",
                eid=engagement_id,
                acid=ac_id,
                title=title,
                impact=impact,
                status=status,
                step_ids=step_ids,
            )
            for i, sid in enumerate(step_ids, 1):
                s.run(
                    "MATCH (ac:AttackChain {engagement_id: $eid, id: $acid}) "
                    "OPTIONAL MATCH (f:Finding {engagement_id: $eid, id: $sid}) "
                    "OPTIONAL MATCH (h:Hypothesis {engagement_id: $eid, id: $sid}) "
                    "WITH ac, coalesce(f, h) AS step WHERE step IS NOT NULL "
                    "MERGE (ac)-[:STEP {n: $n}]->(step)",
                    eid=engagement_id,
                    acid=ac_id,
                    sid=sid,
                    n=i,
                )
        return status

    def get_attack_chains(self, engagement_id: str) -> list[JSON]:
        """Return all attack chains with their ordered steps. Single query."""
        cypher = (
            "MATCH (ac:AttackChain {engagement_id: $eid}) "
            "OPTIONAL MATCH (ac)-[r:STEP]->(step) "
            "WITH ac, r, step ORDER BY r.n "
            "RETURN ac.id AS id, ac.title AS title, ac.impact AS impact, "
            "ac.status AS status, "
            "collect({n: r.n, id: step.id, label: labels(step)[0], "
            "title: coalesce(step.title, step.text)}) AS steps "
            "ORDER BY id"
        )
        with self._driver.session() as s:
            rows = list(s.run(cypher, eid=engagement_id))
        return [
            {
                "id": r["id"],
                "title": r["title"],
                "impact": r["impact"],
                "status": r["status"],
                "steps": [st for st in r["steps"] if st.get("id") is not None],
            }
            for r in rows
        ]

    def attack_chain_count(self, engagement_id: str) -> int:
        with self._driver.session() as s:
            rec = s.run(
                "MATCH (ac:AttackChain {engagement_id: $eid}) RETURN count(ac) AS n",
                eid=engagement_id,
            ).single()
        return int(rec["n"]) if rec else 0

    def missing_steps(self, engagement_id: str, step_ids: list[str]) -> list[str]:
        """Step ids that reference no Finding/Hypothesis node — ARTEX lineage
        enforcement: a chain step that doesn't exist yet must be rejected at
        create time, not silently dropped by the STEP-edge match."""
        if not step_ids:
            return []
        with self._driver.session() as s:
            rec = s.run(
                "UNWIND $ids AS sid "
                "OPTIONAL MATCH (f:Finding {engagement_id: $eid, id: sid}) "
                "OPTIONAL MATCH (h:Hypothesis {engagement_id: $eid, id: sid}) "
                "WITH sid, coalesce(f, h) AS node "
                "WHERE node IS NULL RETURN collect(sid) AS missing",
                eid=engagement_id,
                ids=step_ids,
            ).single()
        return list(rec["missing"]) if rec and rec["missing"] else []

    def chain_frontier(self, engagement_id: str, ac_id: str) -> JSON | None:
        """The next dispatchable chain step, ARTEX-style: a step is MET when
        its finding exists AND is validated (scored). The frontier is the
        first non-met step — dispatching anything past it skips lineage."""
        chains: list[dict[str, Any]] = self.get_attack_chains(engagement_id)  # type: ignore[assignment]
        chain = next((c for c in chains if c["id"] == ac_id), None)
        if chain is None:
            return None
        with self._driver.session() as s:
            rows = list(
                s.run(
                    "UNWIND $ids AS sid "
                    "OPTIONAL MATCH (f:Finding {engagement_id: $eid, id: sid}) "
                    "OPTIONAL MATCH (h:Hypothesis {engagement_id: $eid, id: sid}) "
                    "RETURN sid, coalesce(f, h) AS node, "
                    "f.severity AS severity, labels(coalesce(f, h))[0] AS label",
                    eid=engagement_id,
                    ids=[st["id"] for st in chain["steps"]],
                )
            )
        state = {r["sid"]: (r["node"], r["severity"], r["label"]) for r in rows}
        for st in chain["steps"]:
            node, severity, label = state.get(st["id"], (None, None, None))
            if node is None:
                return {
                    "chain_id": ac_id,
                    "next_step": st["id"],
                    "state": "gap",
                    "message": (
                        f"step {st['id']} has no finding/hypothesis node — "
                        "produce evidence and record it first"
                    ),
                }
            if label == "Finding" and severity is not None:
                continue  # met
            state_word = "unvalidated finding" if label == "Finding" else "hypothesis"
            return {
                "chain_id": ac_id,
                "next_step": st["id"],
                "state": "frontier",
                "message": (
                    f"dispatch {st['id']} ({state_word}) — every earlier step "
                    "is met; do not work past it"
                ),
            }
        return {
            "chain_id": ac_id,
            "next_step": None,
            "state": "complete",
            "message": "all steps met",
        }

    def retest_context(self, engagement_id: str, finding_id: str) -> JSON | None:
        """Finding + its supporting evidence chain, for targeted re-verification."""
        cypher = (
            "MATCH (f:Finding {engagement_id: $eid, id: $fid}) "
            "OPTIONAL MATCH (h:Hypothesis)-[:DERIVES]->(f) "
            "OPTIONAL MATCH (h)-[:SUPPORTED_BY]->(e:Evidence) "
            "RETURN f.id AS id, f.title AS title, f.severity AS severity, "
            "f.justification AS justification, "
            "collect(DISTINCT {id: e.id, tool: e.tool, summary: e.summary, "
            "raw_path: e.raw_path}) AS evidence"
        )
        with self._driver.session() as s:
            rec = s.run(cypher, eid=engagement_id, fid=finding_id).single()
        if rec is None or rec["id"] is None:
            return None
        return {
            "id": rec["id"],
            "title": rec["title"],
            "severity": rec["severity"],
            "justification": rec["justification"],
            "evidence": [e for e in rec["evidence"] if e.get("id") is not None],
        }

    def record_retest(
        self, engagement_id: str, finding_id: str, verdict: str, summary: str
    ) -> None:
        with self._driver.session() as s:
            s.run(
                "MATCH (f:Finding {engagement_id: $eid, id: $fid}) "
                "SET f.retest_verdict=$verdict, f.retest_summary=$summary, "
                "f.retest_at=datetime()",
                eid=engagement_id,
                fid=finding_id,
                verdict=verdict,
                summary=summary,
            )


def _main() -> int:
    if "--smoke" not in sys.argv:
        print("usage: python -m jcyber.clients.memgraph --smoke")
        return 2
    uri = os.environ.get("MEMGRAPH_URI", "bolt://127.0.0.1:7687")
    try:
        store = MemgraphStore.connect(uri)
        try:
            ok = store.ping()
        finally:
            store.close()
    except Exception as e:  # noqa: BLE001 - a smoke check reports any connectivity failure
        print(f"memgraph smoke FAILED @ {uri}: {type(e).__name__}: {e}")
        return 1
    print(f"memgraph smoke ok: {ok} @ {uri}")
    return 0 if ok == 1 else 1


if __name__ == "__main__":
    raise SystemExit(_main())
