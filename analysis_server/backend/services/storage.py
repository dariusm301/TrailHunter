
import json
from services.validator import compute_hash
from datetime import datetime, timezone
from models.events import NormalizedEvent
from detection.models import DetectionReport, DetectionFinding
import shutil
from config import DATA_DIR
from models.auth import Collection


COLLECTIONS_ROOT = DATA_DIR / "collections"


class CollectionStorage:
    def __init__(self, collection_id: str,  hostname: str, db_session):
        self.hostname = hostname
        self.db_session = db_session
        self.base_path = COLLECTIONS_ROOT / collection_id
        self.raw_path = self.base_path / "raw"
        self.processed_path = self.base_path / "processed"
        self.reports_path = self.base_path / "reports"
        self.graphs_path = self.base_path / "graphs"
        self.collection_id = collection_id
        self.timestamp = datetime.now(timezone.utc).isoformat()

    @classmethod
    def create(cls, hostname: str, user_id: str, db_session,  token_id: str | None = None) -> "CollectionStorage":
        """Generate a new collection storage instance with a unique timestamp."""
        record = Collection(user_id=user_id, hostname=hostname,
                            name = f"{hostname}_{datetime.now(timezone.utc).isoformat()}",
                            token_id=token_id,)
        db_session.add(record)
        db_session.commit()
        instance = cls(record.id, hostname, db_session)
        instance._create_dirs()
        return instance

    @classmethod
    def load(cls, collection_id: str, user_id: str, db_session) -> "CollectionStorage":
        """Load an existing collection (for later analysis)."""
        record = db_session.query(Collection).filter(Collection.id == collection_id, Collection.user_id == user_id).first()
        if not record:
            raise FileNotFoundError(f"Collection not found: {collection_id}")
        instance = cls(collection_id, record.hostname, db_session)
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
        if summary and summary.get("sha256") and summary.get("sha256").lower() != provided_hash.lower():
            return False
        summary.update({
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "sha256": provided_hash.lower(),
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
    def list_collections(user_id: str, db_session) -> list[str]:
        """List all available collections in the root directory."""
        record = db_session.query(Collection).filter(Collection.user_id == user_id).all()
        return [r.id for r in record]
    
    def delete(self):
        """Delete this collection and all its data."""
        if self.base_path.exists():
            shutil.rmtree(self.base_path)
        record = self.db_session.query(Collection).filter(
            Collection.id == self.collection_id
        ).first()
        if record:
            self.db_session.delete(record)
            self.db_session.commit()