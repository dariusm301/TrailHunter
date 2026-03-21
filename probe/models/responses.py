from pydantic import BaseModel

class CollectResponse(BaseModel):
    status: str
    hostname: str
    collected_at: str