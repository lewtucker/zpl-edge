from __future__ import annotations

import json
import threading
from pathlib import Path


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            self._f.write(line)
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            self._f.close()
