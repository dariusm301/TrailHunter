from pathlib import Path
import json
from config import DATA_DIR
import base64
import hashlib
import shutil
import logging

logger = logging.getLogger(__name__)

CHUNK_SIZE = 32 * 1024

def iter_file_chunks(path: Path, chunk_size: int = CHUNK_SIZE):
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def list_collections() -> list[dict]:
    collections = []

    if not DATA_DIR.exists():
        return collections

    for hostname_dir in sorted(DATA_DIR.iterdir()):
        if not hostname_dir.is_dir():
            continue

        for ts_dir in sorted(hostname_dir.iterdir()):
            if not ts_dir.is_dir():
                continue

            summary_path = ts_dir / "summary.json"
            data_path = ts_dir / "collection.bin"

            if not data_path.exists():
                continue

            entry = {
                "id": f"{hostname_dir.name}/{ts_dir.name}",
                "hostname": hostname_dir.name,
                "timestamp": ts_dir.name,
                "path": str(ts_dir),
                "size_bytes": data_path.stat().st_size,
                "has_summary": summary_path.exists(),
            }

            if summary_path.exists():
                try:
                    with open(summary_path, "r") as f:
                        summary = json.load(f)
                    entry["summary"] = summary
                except (json.JSONDecodeError, OSError):
                    entry["summary"] = None
                    entry["summary_error"] = True
            else:
                entry["summary"] = None

            collections.append(entry)

    collections.sort(key=lambda c: c["timestamp"], reverse=True)
    return collections


def get_collection_path(collection_id: str) -> Path | None:
    if ".." in collection_id or collection_id.startswith("/"):
        return None

    candidate = DATA_DIR / collection_id / "data.bin"
    try:
        candidate = candidate.resolve()
        if DATA_DIR.resolve() not in candidate.parents:
            return None
    except (OSError, RuntimeError):
        return None

    if not candidate.exists():
        return None

    return candidate

def delete_collection(collection_id: str) -> bool:
    if ".." in collection_id or collection_id.startswith("/"):
        return False

    target = DATA_DIR / collection_id
    try:
        target = target.resolve()
        if DATA_DIR.resolve() not in target.parents:
            return False
    except (OSError, RuntimeError):
        return False

    if not target.exists() or not target.is_dir():
        return False

    shutil.rmtree(target)

    hostname_dir = target.parent
    try:
        if hostname_dir != DATA_DIR and not any(hostname_dir.iterdir()):
            hostname_dir.rmdir()
    except OSError:
        pass

    return True
