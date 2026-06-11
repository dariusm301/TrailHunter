from pydantic import BaseModel

class Metadata(BaseModel):
    hostname: str
    collected_at: str
    os_version: str

class Modules(BaseModel):
    event_logs: dict
    processes: dict
    network: dict
    registry: dict
    scheduled_tasks: dict
    web_logs: dict

class ModuleHashes(BaseModel):
    event_logs: str
    processes: str
    network: str
    registry: str
    scheduled_tasks: str
    web_logs: str

class CollectionPayload(BaseModel):
    metadata: Metadata
    modules: Modules
    module_hashes: ModuleHashes

class CollectionSummary(BaseModel):
    collector_ip: dict[str, list[str]]
