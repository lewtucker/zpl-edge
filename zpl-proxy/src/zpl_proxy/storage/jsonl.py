from __future__ import annotations

import json
import os
import threading
from pathlib import Path


class JsonlWriter:
    """Append-only JSONL forensic log with size-based rotation.

    When the file exceeds ``max_bytes`` it rotates to ``<path>.1`` (keeping
    ``backups`` generations) and starts fresh — so the local forensic capture stays
    bounded. ``max_bytes=0`` disables rotation.
    """

    def __init__(self, path: Path, max_bytes: int = 0, backups: int = 2) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._max_bytes = max_bytes
        self._backups = backups
        self._f = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def _rotate_locked(self) -> None:
        self._f.close()
        # shift .1→.2 … and current→.1, dropping the oldest
        for i in range(self._backups, 0, -1):
            src = self._path if i == 1 else self._path.with_suffix(self._path.suffix + f".{i-1}")
            dst = self._path.with_suffix(self._path.suffix + f".{i}")
            if src.exists():
                os.replace(src, dst)
        self._f = open(self._path, "a", encoding="utf-8")

    def write(self, record: dict) -> None:
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            if self._max_bytes and self._f.tell() + len(line.encode("utf-8")) > self._max_bytes:
                self._rotate_locked()
            self._f.write(line)
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            self._f.close()
