import json
from pathlib import Path
from config import DATA_DIR
from models import CollectionPayload

async def save(payload: CollectionPayload):
    host_dir = DATA_DIR / payload.metadata.hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    timestamp = payload.metadata.collected_at.replace(":", "-")
    filename = host_dir / f"{timestamp}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload.model_dump(), f, indent=2)