import json
from pathlib import Path
from config import DATA_DIR
from models.collection import CollectionPayload, CollectionSummary

async def save(payload: CollectionPayload, summary: CollectionSummary = None) -> None:
    host_dir = DATA_DIR / payload.metadata.hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    timestamp = payload.metadata.collected_at.replace(":", "-")
    filename = host_dir / timestamp / "collection.json"
    filename.parent.mkdir(parents=True, exist_ok=True)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload.model_dump(), f, indent=2)

    summary_file = host_dir / timestamp / "summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)

    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary.model_dump() if summary else None, f, indent=2)