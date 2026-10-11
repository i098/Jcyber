"""In-memory fakes for the ports. Tests use these instead of real backends."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from jcyber.types import JSON, Evidence


class FakeGraph:
    def __init__(self, projection: JSON | None = None, report: JSON | None = None) -> None:
        self.projection: JSON = (
            projection
            if projection is not None
            else {
                "phase": "recon",
                "open_hypotheses": [],
                "validated_findings": [],
                "recent_evidence": [],
                "tools_run": [],
                "unscored_findings": [],
                "attack_chains": [],
            }
        )
        self.decisions: list[JSON] = []
        self.evidence: list[Evidence] = []
        self.verdicts: list[tuple[str, str, float]] = []
        self._seen: set[str] = set()
        self.report: JSON = report if report is not None else {"engagement": "", "findings": []}
        self.chains: list[dict[str, JSON]] = []
        self.assets: dict[str, dict[str, Any]] = {}
        self.findings: list[dict[str, JSON]] = []
        self.hypothesis_ids: set[str] = set()
        self.validated: set[str] = set()
        self.retests: list[tuple[str, str, str]] = []

    def project_state(self, engagement_id: str) -> JSON:
        return self.projection

    def report_data(self, engagement_id: str) -> JSON:
        return self.report

    def write_decision(self, engagement_id: str, record: JSON) -> None:
        self.decisions.append(record)

    def decision_log(self, engagement_id: str) -> list[JSON]:
        return list(self.decisions)

    def insert_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self._seen.add(ev.sha256)

    def evidence_targets(self, engagement_id: str) -> list[str]:
        return [ev.target for ev in self.evidence]

    def upsert_assets(self, engagement_id: str, assets: list) -> None:
        for a in assets:
            self.assets[a.value] = {"kind": a.kind, "parent": a.parent, "evidence": 0}

    def link_evidence(self, engagement_id: str, evidence_id: str, asset_value: str) -> None:
        if asset_value in self.assets:
            self.assets[asset_value]["evidence"] += 1

    def asset_coverage(self, engagement_id: str) -> list[dict[str, Any]]:
        return [
            {"kind": v["kind"], "value": k, "evidence_count": v["evidence"]}
            for k, v in sorted(self.assets.items())
        ]

    def seen_sha256(self, engagement_id: str, sha256: str) -> bool:
        return sha256 in self._seen

    def apply_verdict(
        self, engagement_id: str, hypothesis_id: str, verdict: str, support: float
    ) -> None:
        self.verdicts.append((hypothesis_id, verdict, support))

    def create_hypothesis(self, engagement_id: str, hid: str, text: str, evidence_id: str) -> None:
        self.hypothesis_ids.add(hid)

    def create_finding(
        self,
        engagement_id: str,
        fid: str,
        title: str,
        hypothesis_id: str,
        endpoint: str = "",
        dedup_key: str = "",
    ) -> None:
        self.findings.append(
            {"id": fid, "title": title, "endpoint": endpoint, "dedup_key": dedup_key}
        )

    def find_similar_findings(self, engagement_id: str, dedup_key: str) -> list[dict[str, JSON]]:
        return [
            {"id": f["id"], "title": f["title"]}
            for f in self.findings
            if f["dedup_key"] == dedup_key
        ][:6]

    def score_finding(self, engagement_id: str, fid: str, severity: int) -> None:
        self.validated.add(fid)

    def create_attack_chain(
        self, engagement_id: str, ac_id: str, title: str, impact: str, step_ids: list[str]
    ) -> str:
        status = "demonstrated" if all(s.startswith("F-") for s in step_ids) else "theoretical"
        steps: list[JSON] = list(step_ids)
        self.chains.append(
            {"id": ac_id, "title": title, "impact": impact, "status": status, "steps": steps}
        )
        return status

    def get_attack_chains(self, engagement_id: str) -> list[JSON]:
        return list(self.chains)

    def attack_chain_count(self, engagement_id: str) -> int:
        return len(self.chains)

    def missing_steps(self, engagement_id: str, step_ids: list[str]) -> list[str]:
        known = {f["id"] for f in self.findings} | self.hypothesis_ids
        return [s for s in step_ids if s not in known]

    def chain_frontier(self, engagement_id: str, ac_id: str) -> JSON | None:
        chains: list[dict[str, Any]] = self.chains
        chain = next((c for c in chains if c["id"] == ac_id), None)
        if chain is None:
            return None
        for sid in chain["steps"]:
            if sid not in self.validated:
                return {
                    "chain_id": ac_id,
                    "next_step": sid,
                    "state": "frontier",
                    "message": f"dispatch {sid}",
                }
        return {
            "chain_id": ac_id,
            "next_step": None,
            "state": "complete",
            "message": "all steps met",
        }

    def retest_context(self, engagement_id: str, finding_id: str) -> JSON | None:
        f = next((f for f in self.findings if f["id"] == finding_id), None)
        if f is None:
            return None
        return {
            "id": finding_id,
            "title": f.get("title"),
            "severity": f.get("severity"),
            "justification": f.get("justification"),
            "evidence": f.get("evidence", []),
        }

    def record_retest(
        self, engagement_id: str, finding_id: str, verdict: str, summary: str
    ) -> None:
        self.retests.append((finding_id, verdict, summary))

    def evidence_index(self, engagement_id: str) -> list[JSON]:
        return [
            {"id": ev.id, "tool": ev.tool, "target": ev.target, "raw_path": ev.raw_path}
            for ev in self.evidence
        ]


class FakeHands:
    def __init__(
        self, output: str = "line one\nline two", outputs: list[str] | None = None
    ) -> None:
        self.output = output
        self.outputs = outputs
        self.calls: list[tuple[str, dict[str, JSON]]] = []

    def is_tool_available(self, mcp_name: str) -> bool | None:
        return None

    def call(self, tool: str, params: Mapping[str, JSON]) -> str:
        self.calls.append((tool, dict(params)))
        if self.outputs is not None:
            return self.outputs.pop(0)
        return self.output


class FakeMemory:
    def __init__(self, priors: JSON | None = None) -> None:
        self.priors = priors
        self.commits: list[tuple[str, JSON]] = []

    def recall(self, engagement_id: str, scope: JSON) -> JSON:
        return self.priors

    def commit(self, engagement_id: str, atoms: JSON) -> None:
        self.commits.append((engagement_id, atoms))


class FakeProxy:
    def __init__(self, findings: list[JSON] | None = None) -> None:
        self._findings = findings or []

    def findings(self, engagement_id: str) -> list[JSON]:
        return list(self._findings)
