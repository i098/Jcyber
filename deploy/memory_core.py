"""Standalone SQLite memory-core: the thin long-term-brain backend behind the
two-method seam (schema/tencentdb/memory-interface.md), PLAN D1 option (b) --
"memory-core standalone (SQLite) with our own thin skill store". It speaks the
HTTP form of the seam (POST /recall, POST /commit) so
jcyber.clients.tencentdb.TencentMemory talks to it unchanged; swap for hosted
TencentDB later without touching the loop.

Atoms ACCUMULATE across engagements (append + dedup by text); recall matches
on the scope target/description so a NEW engagement surfaces prior lessons
from similar targets -- that is the whole point of long-term memory.

Run:  uv run python deploy/memory_core.py [port] [db_path]
Env:  JCYBER_MEMORY_URL=http://127.0.0.1:8130
"""

from __future__ import annotations

import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_PATH = "/tmp/jcyber_memory.db"
PRIORS_CAP = 2000  # chars, per memory-interface.md


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS atoms ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " engagement TEXT NOT NULL,"
        " kind TEXT NOT NULL DEFAULT 'atom',"
        " text TEXT NOT NULL,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now')), "
        " UNIQUE (engagement, text))"
    )
    return conn


def do_commit(conn: sqlite3.Connection, engagement: str, outbox: dict) -> dict:
    """Append atoms (dedup on engagement+text). Returns per-item results."""
    results: list[str] = []
    atoms = outbox.get("atoms")
    if isinstance(atoms, list):
        for text in atoms:
            if not isinstance(text, str) or not text.strip():
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO atoms (engagement, text) VALUES (?, ?)",
                (engagement, text.strip()),
            )
            results.append("created" if cur.rowcount else "duplicate")
    else:
        # legacy shape: whole-outbox blob per engagement
        conn.execute(
            "INSERT INTO atoms (engagement, text) VALUES (?, ?) "
            "ON CONFLICT(engagement, text) DO NOTHING",
            (engagement, json.dumps(outbox)),
        )
        results.append("created")
    conn.commit()
    return {"results": results}


def do_recall(conn: sqlite3.Connection, engagement: str, scope: dict) -> dict:
    """Priors for this engagement: atoms from the SAME engagement first, then
    atoms from other engagements whose text mentions the scope target or any
    scope word (>= 4 chars). Capped to PRIORS_CAP chars."""
    target = str(scope.get("target") or "").lower()
    host = target.split("//")[-1].split("/")[0].split(":")[0]
    description = str(scope.get("description") or "").lower()
    words = [w for w in description.replace(",", " ").split() if len(w) >= 4][:8]

    lines: list[str] = []
    # NOTE: LIKE patterns are C strings under the hood — never pass an empty
    # or NUL-containing pattern (it truncates to "%" and matches everything).
    if description:
        rows = conn.execute(
            "SELECT engagement, kind, text FROM atoms "
            "WHERE engagement = ? OR text LIKE ? OR text LIKE ? "
            "ORDER BY id DESC LIMIT 200",
            (engagement, f"%{host}%", f"%{description}%"),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT engagement, kind, text FROM atoms "
            "WHERE engagement = ? OR text LIKE ? "
            "ORDER BY id DESC LIMIT 200",
            (engagement, f"%{host}%"),
        ).fetchall()
    if not rows and words:
        like = " OR ".join(["text LIKE ?"] * len(words))
        rows = conn.execute(
            f"SELECT engagement, kind, text FROM atoms WHERE {like} ORDER BY id DESC LIMIT 200",
            [f"%{w}%" for w in words],
        ).fetchall()
    seen: set[str] = set()
    for eng, kind, text in rows:
        line = f"[{kind}] {text}" if eng != engagement else f"[{kind}] {text}"
        if line in seen:
            continue
        seen.add(line)
        if sum(len(x) + 1 for x in lines) + len(line) > PRIORS_CAP:
            lines.append("(priors truncated)")
            break
        lines.append(line)
    return {"priors": "\n".join(lines), "count": len(lines)}


class Handler(BaseHTTPRequestHandler):
    def _read(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw or b"{}")
        return data if isinstance(data, dict) else {}

    def _send(self, obj: object, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        req = self._read()
        engagement = str(req.get("engagement", ""))
        conn = _conn()
        try:
            if self.path == "/commit":
                self._send(do_commit(conn, engagement, req.get("outbox") or {}))
            elif self.path == "/recall":
                self._send(do_recall(conn, engagement, req.get("scope") or {}))
            else:
                self._send({"error": "not found"}, 404)
        finally:
            conn.close()

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8130) -> None:
    server = HTTPServer((host, port), Handler)
    print(f"memory-core on http://{host}:{port} db={DB_PATH}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8130
    if len(sys.argv) > 2:
        DB_PATH = sys.argv[2]
    serve(port=port_arg)
