from pydantic import BaseModel
from typing import Optional

class CollectResponse(BaseModel):
    status: str
    hostname: str
    collected_at: str
    forwarded_to_analysis_server: bool = False
    forward_error: Optional[str] = None
