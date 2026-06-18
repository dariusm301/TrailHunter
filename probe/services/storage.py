import json
from pathlib import Path
from config import DATA_DIR
from models.collection import CollectionSummary

async def save(raw_bytes: bytes, metadata, summary: CollectionSummary = None) -> None:
    host_dir = DATA_DIR / metadata.hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    timestamp = metadata.collected_at.replace(":", "-")
    filename = host_dir / timestamp / "collection.bin"
    filename.parent.mkdir(parents=True, exist_ok=True)

    with open(filename, "wb") as f:
        f.write(raw_bytes)

    summary_file = host_dir / timestamp / "summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)

    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary.model_dump() if summary else None, f, indent=2)