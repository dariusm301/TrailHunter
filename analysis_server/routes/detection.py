from fastapi import APIRouter, HTTPException, Header, Request
from detection.engine import DetectionEngine
from detection.rules.web_logs import get_web_rules
from detection.rules.security import get_security_rules
from detection.rules.sysmon import get_sysmon_rules
from detection.rules.network import get_network_rules
from detection.rules.registry import get_registry_rules
from detection.rules.wmi import get_wmi_rules
from detection.rules.processes import get_process_rules
from services.storage import CollectionStorage
from detection.engine import DetectionReport
from pydantic import BaseModel

router = APIRouter()

class DetectRequest(BaseModel):
    collection_id: str
    sources: list[str] = []  

rules_functions = [get_web_rules, get_security_rules, get_sysmon_rules, get_network_rules, get_registry_rules, get_wmi_rules, get_process_rules]
sources = ["security", "sysmon", "web_logs", "network", "registry", "wmi", "processes"]  

@router.post("/api/detect")
async def detect(
    request : DetectRequest,
):

    try:
        storage_collection = CollectionStorage.load(request.collection_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")

    # Load detection rules
    per_event = []
    aggregate = []
    for get_rules in rules_functions:
        per_event.extend(get_rules()[0])
        aggregate.extend(get_rules()[1])

    engine = DetectionEngine(per_event, aggregate)

    #Load normalized data for system logs
    for source in sources:
        logs = storage_collection.load_channel(source)
        if not logs:
            continue
        report = engine.analyze(
            events=logs,
            collection_id=request.collection_id,
            source=source,
        )

        # Save the detection report
        storage_collection.save_report(source, report)

    return { "status" : "success"}
