from pydantic import BaseModel, Field
from typing import Optional
import uuid
from enum import Enum
from datetime import datetime

class EventFields(BaseModel):
    action : str | None = None
    category : str | None = None
    code : str | None = None
    created : datetime | None = None
    dataset : str | None = None
    module : str | None = None
    original : bytes | None = None
    provider : str | None = None
    risk_score : float | None = None
    severity : int | None = None
    severity_label : str | None = None
    reason : str | None = None

class OSFields(BaseModel):
    family: str | None = None
    full: str | None = None

class HostFields(BaseModel):
    architecture : str | None = None
    domain : str | None = None
    hostname : str | None = None
    ip : str | None = None
    name : str | None = None
    os: OSFields | None = None
    mac : str | None = None

class UserFields(BaseModel):
    name : str | None = None
    domain : str | None = None
    id : str | None = None

class ProcessFields(BaseModel):
    args : list[str] | None = None
    args_count : int | None = None
    command_line : str | None = None
    end : datetime | None = None
    entity_id : str | None = None
    executable : str | None = None
    hash_sha256 : str | None = None
    exit_code : int | None = None
    interactive : bool | None = None
    name : str | None = None
    pid : int | None = None
    start : datetime | None = None
    parent: ProcessFields | None = None

ProcessFields.model_rebuild()

class NetworkFields(BaseModel):
    protocol: str | None = None
    transport: str | None = None
    direction: str | None = None
    # Custom fields
    name: str | None = None
    gateway : str | None = None
    dns_servers : str | None = None

class SourceFields(BaseModel):
    address: str | None = None
    port: int | None = None

class DestinationFields(BaseModel):
    address: str | None = None
    port: int | None = None


class RegistryFields(BaseModel):
    path : str | None = None
    value : str | None = None
    data : str | None = None

class WinLogsFields (BaseModel):
    channel : str | None = None
    event_id : int | None = None
    provider_name : str | None = None
    computer_name : str | None = None
    extra : str | None = None


class HTTPFields(BaseModel):
    request_method: str | None = None
    response_status_code: int | None = None
    user_agent : str | None = None

class UrlFields(BaseModel):
    original: str | None = None
    path: str | None = None

class FileFields(BaseModel):
    path : str | None = None
    name : str | None = None
    created : datetime | None = None

class TargetFields(BaseModel):
    process: ProcessFields | None = None

class DNSQuestionFields(BaseModel):
    name: str | None = None
    type: str | None = None

class DNSAnswerFields(BaseModel):
    data: str | None = None
    type: str | None = None

class DNSFields(BaseModel):
    question: DNSQuestionFields | None = None
    answers: list[DNSAnswerFields] | None = None
    response_code: str | None = None

class GroupFields(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    id: Optional[str] = None          
    member_id: Optional[str] = None 
    member_name: Optional[str] = None

class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    event: EventFields | None = None
    host: HostFields | None = None
    user: UserFields | None = None
    process: ProcessFields | None = None
    target : TargetFields | None = None
    network: NetworkFields | None = None
    source: SourceFields | None = None
    destination: DestinationFields | None = None
    registry: RegistryFields | None = None
    winlog: WinLogsFields | None = None
    http: HTTPFields | None = None
    url: UrlFields | None = None
    file: FileFields | None = None
    dns : DNSFields | None = None
    group: GroupFields | None = None