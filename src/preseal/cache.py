"""Response cache — sqlite3-backed LLM response caching with TTL."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional


def _cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    return Path(base) / "preseal"


def _cache_key(url: str, body: str) -> str:
    return hashlib.sha256(f"{url}\n{body}".encode()).hexdigest()


class ResponseCache:
    def __init__(self, db_path: Optional[Path] = None):
        self._ttl = int(os.environ.get("PRESEAL_CACHE_TTL", "86400"))
        self._max_size = int(os.environ.get("PRESEAL_CACHE_MAX_SIZE", str(50 * 1024 * 1024)))
        self._hits = 0
        self._misses = 0
        self._lock = threading.Lock()
        self._db_path = db_path or (_cache_dir() / "responses.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, value TEXT, created_at REAL, size INTEGER)"
            )
            self._conn.commit()
            self._prune_expired()
        except Exception:
            self._conn = None

    def _prune_expired(self) -> None:
        if not self._conn:
            return
        try:
            cutoff = time.time() - self._ttl
            self._conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
            self._conn.commit()
        except Exception:
            pass

    def get(self, key: str) -> Optional[str]:
        if not self._conn:
            self._misses += 1
            return None
        with self._lock:
            try:
                cutoff = time.time() - self._ttl
                row = self._conn.execute(
                    "SELECT value FROM cache WHERE key = ? AND created_at >= ?",
                    (key, cutoff),
                ).fetchone()
                if row:
                    self._hits += 1
                    return row[0]
                self._misses += 1
                return None
            except Exception:
                self._misses += 1
                return None

    def put(self, key: str, value: str) -> None:
        if not self._conn:
            return
        with self._lock:
            try:
                self._enforce_size_limit(len(value.encode()))
                self._conn.execute(
                    "INSERT OR REPLACE INTO cache (key, value, created_at, size) VALUES (?, ?, ?, ?)",
                    (key, value, time.time(), len(value.encode())),
                )
                self._conn.commit()
            except Exception:
                pass

    def _enforce_size_limit(self, incoming_size: int) -> None:
        if not self._conn:
            return
        row = self._conn.execute("SELECT COALESCE(SUM(size), 0) FROM cache").fetchone()
        current_size = row[0] if row else 0
        if current_size + incoming_size > self._max_size:
            # Evict oldest entries until we have room
            self._conn.execute(
                "DELETE FROM cache WHERE key IN "
                "(SELECT key FROM cache ORDER BY created_at ASC LIMIT "
                "(SELECT COUNT(*)/4 + 1 FROM cache))"
            )
            self._conn.commit()

    def clear(self) -> None:
        if not self._conn:
            return
        with self._lock:
            try:
                self._conn.execute("DELETE FROM cache")
                self._conn.commit()
            except Exception:
                pass
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict:
        size = 0
        if self._conn:
            try:
                row = self._conn.execute("SELECT COALESCE(SUM(size), 0) FROM cache").fetchone()
                size = row[0] if row else 0
            except Exception:
                pass
        return {"hits": self._hits, "misses": self._misses, "size_bytes": size}


def make_cache_key(url: str, body: str) -> str:
    return _cache_key(url, body)
