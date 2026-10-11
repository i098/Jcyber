"""Asset derivation: program-computed hierarchy from evidence target strings.
No model — a URL/host string parses (deterministically) into host ->
service (when a port is present) -> endpoint (when a path is present).
ARTEX-style asset graph: the agent never invents parentage, the code does."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Asset:
    kind: str  # host | service | endpoint
    value: str
    parent: str | None  # parent asset value; None for host roots


def derive_assets(target: str) -> list[Asset]:
    """Parse a host/URL into its asset chain. Bare host -> [host].
    host:port/path -> [host, service, endpoint]. Endpoints without a port
    attach to the host directly."""
    u = urlsplit(target if "://" in target else "http://" + target)
    host = (u.hostname or "").lower()
    if not host:
        return []
    assets = [Asset(kind="host", value=host, parent=None)]
    if u.port is not None:
        service = f"{host}:{u.port}"
        assets.append(Asset(kind="service", value=service, parent=host))
    path = (u.path or "").rstrip("/")
    if path and path != "":
        parent = assets[-1].value
        endpoint = f"{parent}{path}"
        assets.append(Asset(kind="endpoint", value=endpoint, parent=parent))
    return assets
