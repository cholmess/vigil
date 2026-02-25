"""SQLite storage for conversation turns from forensic scans and OTLP ingestion."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from vigil.forensics.models import ConversationTurn


class TurnStore:
    """SQLite-backed store for ConversationTurn objects."""

    def __init__(self, db_path: str = "vigil-forensics.db"):
        self.db_path = db_path
        self._ensure_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    turn_index INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    source_format TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_turns_conv ON turns(conversation_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_turns_ts ON turns(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_turns_role ON turns(role)")

    def insert(self, turn: ConversationTurn) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO turns
                (conversation_id, turn_index, role, content, timestamp, metadata, source_format)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    turn.conversation_id,
                    turn.turn_index,
                    turn.role,
                    turn.content,
                    turn.timestamp.astimezone(timezone.utc).isoformat(),
                    json.dumps(turn.metadata),
                    turn.source_format,
                ),
            )

    def insert_many(self, turns: list[ConversationTurn]) -> int:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO turns
                (conversation_id, turn_index, role, content, timestamp, metadata, source_format)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        t.conversation_id,
                        t.turn_index,
                        t.role,
                        t.content,
                        t.timestamp.astimezone(timezone.utc).isoformat(),
                        json.dumps(t.metadata),
                        t.source_format,
                    )
                    for t in turns
                ],
            )
        return len(turns)

    def list_turns(
        self,
        *,
        conversation_id: str | None = None,
        role: str | None = None,
        since: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[ConversationTurn]:
        clauses = []
        params: list = []
        if conversation_id:
            clauses.append("conversation_id = ?")
            params.append(conversation_id)
        if role:
            clauses.append("role = ?")
            params.append(role)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM turns {where} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_turn(row) for row in rows]

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) AS c FROM turns").fetchone()["c"]

    def clear(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM turns")
            return cur.rowcount

    @staticmethod
    def _row_to_turn(row: sqlite3.Row) -> ConversationTurn:
        return ConversationTurn(
            conversation_id=row["conversation_id"],
            turn_index=int(row["turn_index"]),
            role=row["role"],
            content=row["content"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            metadata=json.loads(row["metadata"]),
            source_format=row["source_format"],
        )
