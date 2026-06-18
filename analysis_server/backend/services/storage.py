
import json
import hashlib
from pathlib import Path
from services.validator import compute_hash
from datetime import datetime, timezone
from models.events import NormalizedEvent
from detection.models import DetectionReport, DetectionFinding
import shutil


COLLECTIONS_ROOT = Path("collections")


class CollectionStorage:
    def __init__(self, hostname: str, timestamp: str):
        self.hostname = hostname
        self.timestamp = timestamp
        self.base_path = COLLECTIONS_ROOT / hostname / timestamp
        self.raw_path = self.base_path / "raw"
        self.processed_path = self.base_path / "processed"
        self.reports_path = self.base_path / "reports"
        self.graphs_path = self.base_path / "graphs"

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
        hostname, timestamp = collection_id.split("/", 1)
        instance = cls(hostname, timestamp)
        if not instance.base_path.exists():
            raise FileNotFoundError(f"Collection not found: {instance.base_path}")
        return instance

    def _create_dirs(self):
        self.raw_path.mkdir(parents=True, exist_ok=True)
        self.processed_path.mkdir(parents=True, exist_ok=True)
        self.reports_path.mkdir(parents=True, exist_ok=True)
        self.graphs_path.mkdir(parents=True, exist_ok=True)

    def save_raw(self, data: bytes, provided_hash: str) -> bool:
        """Save raw bytes and write the summary. Returns False if the hash does not match."""
        computed = compute_hash(data).lower()
        if computed != provided_hash.lower():
            return False

        (self.raw_path / "collection.bin").write_bytes(data)

        summary = self.load_summary()
        if summary.get("sha256", "").lower() != provided_hash.lower():
            return False
        
        summary.update({
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "size_bytes": len(data),
        })

        self.save_summary(summary)
        return True

    def load_raw(self) -> bytes:
        return (self.raw_path / "collection.bin").read_bytes()

    def save_channel(self, channel: str, events: list[NormalizedEvent]):
        """Save the normalized events for a specific channel."""
        path = self.processed_path / f"{channel}.json"
        events_dict = {event.id: event for event in events}
        path.write_text(json.dumps(
            {eid: e.model_dump(mode="json") for eid, e in events_dict.items()},
            indent=2,
        ))
        return events_dict

    def load_channel(self, channel: str) -> dict[str, NormalizedEvent]:
        """Load normalized events for a channel, indexed by event ID."""
        path = self.processed_path / f"{channel}.json"
        if not path.exists():
            return {}
        
        raw = json.loads(path.read_text())
        return {eid: NormalizedEvent.model_validate(e) for eid, e in raw.items()}
    
    def load_all_channels(self) -> dict[str, NormalizedEvent]:
        """Load all normalized channels for this collection."""
        all_events = {}
        for channel_file in self.processed_path.glob("*.json"):
            all_events.update(self.load_channel(channel_file.stem))
        return all_events

    def save_summary(self, summary: dict):
        path = self.base_path / "summary.json"
        path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    def load_summary(self) -> dict:
        path = self.base_path / "summary.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def available_channels(self) -> list[str]:
        """Return the list of available normalized channels for this collection."""
        return [
            p.stem for p in self.processed_path.glob("*.json") if p.stem != "summary"
        ]

    def __repr__(self):
        return f"<CollectionStorage {self.hostname}/{self.timestamp}>"

    def save_report(self, channel :str, report: DetectionReport):
        path = self.reports_path / f"{channel}.json"
        path.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")

    def load_report(self, channel: str) -> DetectionReport:
        path = self.reports_path / f"{channel}.json"
        if not path.exists():
            raise FileNotFoundError(f"Report not found for channel: {channel}")
        report_data = json.loads(path.read_text(encoding="utf-8"))
        return DetectionReport(**report_data)

    def load_all_reports(self) -> list[DetectionReport]:
        """Load all detection reports for this collection."""
        reports = []
        for report_file in self.reports_path.glob("*.json"):
            channel_name = report_file.stem
            reports.append(self.load_report(channel_name))
        return reports
    
    def load_all_findings(self) -> list[DetectionFinding]:
        """Load all findings from all reports for this collection."""
        findings = []
        for report in self.load_all_reports():
            findings.extend(report.findings)
        return findings

    def save_correlated(self, payload: dict) -> None:
        path = self.graphs_path / "graph.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    def load_correlated(self) -> dict | None:
        if not self.graphs_path.exists():
            return None
        with open(self.graphs_path / "graph.json", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def list_collections() -> list[str]:
        """List all available collections in the root directory."""
        if not COLLECTIONS_ROOT.exists():
            return []
        return [
            f"{p.parent.parent.name}/{p.parent.name}"
            for p in COLLECTIONS_ROOT.glob("*/*/summary.json")
        ]
    
    def delete(self):
        """Delete this collection and all its data."""
        if self.base_path.exists():
            shutil.rmtree(self.base_path)
            
            parent_dir = self.base_path.parent
            if parent_dir.exists() and not any(parent_dir.iterdir()):
                try:
                    parent_dir.rmdir()
                except OSError:
                    pass