import asyncio
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.orm import Session
from services.storage import CollectionStorage
from detection.correlator import Correlator
from detection.fusion import fuse_findings
from services.database import SessionLocal

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="correlate")


@dataclass
class CorrelationJob:
    collection_id: str
    status: str = "running"
    phase: str = "queued"
    progress: Optional[float] = None
    error: Optional[str] = None
    result: Optional[Any] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def envelope(self) -> dict:
        return {
            "status": self.status,
            "phase": self.phase,
            "progress": self.progress,
            "error": self.error,
            "graph": self.result if self.status == "done" else None,
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 1),
        }


_jobs: dict[str, CorrelationJob] = {}
_lock = asyncio.Lock()


def _flatten_ips(raw_ips) -> list:
    if isinstance(raw_ips, dict):
        flat = []
        for v in raw_ips.values():
            flat.extend(v)
        return flat
    if isinstance(raw_ips, list):
        return raw_ips
    if isinstance(raw_ips, str) and raw_ips != "unknown":
        return [raw_ips]
    return []


def _run_correlation(job: CorrelationJob, user_id: str) -> dict:
    db_session = SessionLocal()
    try:
        storage = CollectionStorage.load(collection_id=job.collection_id, user_id=user_id, db_session=db_session)
        job.phase = "loading"
        findings = storage.load_all_findings()
        events = storage.load_all_channels()
        job.phase = "fusing"
        fused = fuse_findings(findings)
        job.phase = "correlating"
        correlator = Correlator(events, fused)
        correlator.build_graph()
        job.phase = "saving"
        summary = storage.load_summary()
        summary["actor_count"] = len(correlator.actor_groups)
        summary["probe"] = summary.get("collector_ip") is not None
        storage.save_summary(summary)
        flat_ips = _flatten_ips(summary.get("collector_ip", {}))
        payload = correlator.serialize(collector_ip=flat_ips)
        storage.save_correlated(payload)
        return payload
    finally:
        db_session.close()


async def start_correlation(collection_id: str, force: bool, user_id: str, db_session: Session) -> CorrelationJob:
    async with _lock:
        existing = _jobs.get(collection_id)
        if existing and existing.status == "running":
            return existing
        if not force:
            try:
                cached = CollectionStorage.load(collection_id=collection_id, user_id=user_id, db_session=db_session).load_correlated()
            except Exception:
                cached = None
            if cached is not None:
                job = CorrelationJob(collection_id, status="done", phase="cached",
                                     result=cached, finished_at=time.time())
                _jobs[collection_id] = job
                return job
        job = CorrelationJob(collection_id)
        _jobs[collection_id] = job

    async def _runner():
        loop = asyncio.get_running_loop()
        try:
            job.result = await loop.run_in_executor(_executor, _run_correlation, job, user_id)
            job.status = "done"
            job.phase = "done"
        except Exception as e:
            job.status = "error"
            job.error = str(e)
            traceback.print_exc()
        finally:
            job.finished_at = time.time()

    asyncio.create_task(_runner())
    return job


def get_job(collection_id: str) -> Optional[CorrelationJob]:
    return _jobs.get(collection_id)