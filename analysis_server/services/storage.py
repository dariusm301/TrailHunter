
import json
import hashlib
from pathlib import Path
from services.validator import compute_hash
from datetime import datetime, timezone
from models.events import NormalizedEvent
from detection.models import DetectionReport


COLLECTIONS_ROOT = Path("collections")


class CollectionStorage:
    def __init__(self, hostname: str, timestamp: str):
        self.hostname = hostname
        self.timestamp = timestamp
        self.base_path = COLLECTIONS_ROOT / hostname / timestamp
        self.raw_path = self.base_path / "raw"
        self.processed_path = self.base_path / "processed"
        self.reports_path = self.base_path / "reports"

    @classmethod
    def create(cls, hostname: str) -> "CollectionStorage":
        """Generate a new collection storage instance with a unique timestamp."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        instance = cls(hostname, timestamp)
        instance._create_dirs()
        return instance

    @classmethod
    def load(cls, collection_id: str) -> "CollectionStorage":
        """Load an existing collection (for later analysis)."""
        # Assuming collection_id is in the format "hostname/timestamp"
        hostname, timestamp = collection_id.split("/", 1)
        instance = cls(hostname, timestamp)
        if not instance.base_path.exists():
            raise FileNotFoundError(f"Collection not found: {instance.base_path}")
        return instance

    def _create_dirs(self):
        self.raw_path.mkdir(parents=True, exist_ok=True)
        self.processed_path.mkdir(parents=True, exist_ok=True)
        self.reports_path.mkdir(parents=True, exist_ok=True)
    # -------------------------
    # RAW
    # -------------------------

    def save_raw(self, data: bytes, provided_hash: str) -> bool:
        """Save raw bytes and write the manifest. Returns False if the hash does not match."""
        computed = compute_hash(data)
        if computed != provided_hash:
            return False

        (self.raw_path / "collection.bin").write_bytes(data)
        manifest = {
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "sha256": computed,
            "size_bytes": len(data),
        }
        (self.base_path / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return True

    def load_raw(self) -> bytes:
        return (self.raw_path / "collection.bin").read_bytes()

    # -------------------------
    # PROCESSED
    # -------------------------

    def save_channel(self, channel: str, events: list[NormalizedEvent]):
        """Save the normalized events for a specific channel."""
        path = self.processed_path / f"{channel}.json"
        path.write_text(json.dumps([e.model_dump(mode="json") for e in events], indent=2))

    def load_channel(self, channel: str) -> list[NormalizedEvent]:
        path = self.processed_path / f"{channel}.json"
        if not path.exists():
            return []
        return [NormalizedEvent(**e) for e in json.loads(path.read_text(encoding="utf-8"))]

    def save_summary(self, summary: dict):
        path = self.base_path / "summary.json"
        path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    def load_summary(self) -> dict:
        path = self.processed_path / "summary.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def save_report(self, channel :str, report: DetectionReport):
        path = self.reports_path / f"{channel}.json"
        path.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")

    def available_channels(self) -> list[str]:
        """Return the list of available normalized channels for this collection."""
        return [
            p.stem for p in self.processed_path.glob("*.json") if p.stem != "summary"
        ]

    def __repr__(self):
        return f"<CollectionStorage {self.hostname}/{self.timestamp}>"