"""Distiller: scan the report data for durable atoms (validated findings,
retired hypotheses) and commit them to the long-term brain. Written at commit
only -- never in the hot path. Atoms carry readable text, not bare ids, so
they recall usefully in FUTURE engagements (cross-engagement priors).
(Skill extraction from working bypasses is deferred to live wiring.)"""

from __future__ import annotations

from typing import Any

from .ports import Memory
from .types import JSON


def distill(engagement: str, report: JSON) -> dict[str, Any]:
    """Extract text atoms from report_data output. Each validated finding
    becomes "<engagement>: <title> — <justification/summary>"; retired
    hypotheses keep their reasoning."""
    atoms: list[str] = []
    if isinstance(report, dict):
        findings = report.get("findings")
        for f in findings if isinstance(findings, list) else []:
            if not isinstance(f, dict):
                continue
            fid = f.get("id", "")
            title = str(f.get("title") or "").strip()
            detail = str(f.get("justification") or f.get("summary") or "").strip()
            if title or detail:
                line = f"{engagement} {fid}: {title}"
                if detail:
                    line += f" — {detail}"
                atoms.append(line)
        retired = report.get("retired_hypotheses")
        for h in retired if isinstance(retired, list) else []:
            if isinstance(h, str):
                atoms.append(f"{engagement} retired hypothesis: {h}")
            elif isinstance(h, dict):
                text = str(h.get("text") or h.get("summary") or "").strip()
                if text:
                    atoms.append(f"{engagement} retired hypothesis: {text}")
    return {"atoms": atoms}


def commit_learnings(memory: Memory, engagement_id: str, report: JSON) -> None:
    memory.commit(engagement_id, distill(engagement_id, report))
