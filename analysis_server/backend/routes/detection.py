from services.database import get_db
from services.dependencies import get_current_user
from models.auth import User
from fastapi import APIRouter, HTTPException, Header, Request, Depends
from sqlalchemy.orm import Session
from detection.engine import DetectionEngine

from detection.correlator import Correlator
from services.storage import CollectionStorage
from detection.engine import DetectionReport
from detection.models import Severity
from pydantic import BaseModel
from detection.rules.auth_rules import get_auth_rules
from detection.rules.connection_rules import get_connection_rules
from detection.rules.processes_rules import get_processes_rules
from detection.rules.powershell_rules import get_powershell_rules
from detection.rules.registry_rules import get_registry_rules
from detection.rules.rules_defense_evasion import get_defense_evasion_rules
from detection.rules.sysmon_rules import get_sysmon_rules
from detection.rules.tasks_rules import get_scheduled_task_rules
from detection.rules.wmi_rules import get_wmi_rules
from detection.rules.web_rules import get_web_rules


router = APIRouter()

class DetectRequest(BaseModel):
    collection_id: str
    sources: list[str] = []  

rules_functions = [get_auth_rules, get_connection_rules, get_processes_rules, get_powershell_rules, get_registry_rules, get_defense_evasion_rules, get_sysmon_rules, get_scheduled_task_rules, get_wmi_rules, get_web_rules]

@router.post("/api/detect")
async def detect(
    request : DetectRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db)
):

    try:
        storage_collection = CollectionStorage.load(request.collection_id, current_user.id, db_session)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")

    per_event = []
    aggregate = []
    for get_rules in rules_functions:
        per_event.extend(get_rules()[0])
        aggregate.extend(get_rules()[1])

    engine = DetectionEngine(per_event, aggregate)

  
    sources = request.sources if request.sources != [] else storage_collection.available_channels()
    summary = storage_collection.load_summary()
    if "finding_counts" not in summary:
        summary["finding_counts"] = {}

    if "max_severity" not in summary:
        summary["max_severity"] = Severity.LOW

    all_findings = []
    for source in sources:
        events = storage_collection.load_channel(source)
        if not events:
            continue
        report = engine.analyze(
            events=events,
            collection_id=request.collection_id,
            source=source,
        )
        summary["finding_counts"][source] = len(report.findings)
        summary["max_severity"] = max(
            summary["max_severity"],
            report.max_severity if report.max_severity else Severity.LOW
        )
        storage_collection.save_report(source, report)

        for f in report.findings:
            all_findings.append({
                "id":             f.id,
                "timestamp":      f.timestamp.isoformat() if f.timestamp else None,
                "rule_id":        f.rule_id,
                "rule_name":      f.rule_name,
                "rule_type":      f.rule_type,
                "severity":       f.severity.value,
                "confidence":     f.confidence,
                "kill_chain":     f.kill_chain_phase.value if f.kill_chain_phase else None,
                "tactic":         f.tactic.value if f.tactic else None,
                "technique_id":   f.technique_id,
                "technique_name": f.technique_name,
                "source":         f.source,
                "description":    f.description,
                "tags":           f.tags,
                "event_count":    f.event_count,
                "entities":       f.entities,
            })

    storage_collection.save_summary(summary)

    return {
        "status":         "success",
        "total_findings": sum(summary["finding_counts"].values()),
        "max_severity":   summary["max_severity"].value if hasattr(summary["max_severity"], "value") else summary["max_severity"],
        "findings":       all_findings,
    }