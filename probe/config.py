from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).parent
COLLECTOR_DIR = BASE_DIR.parent / "collector"
DATA_DIR = BASE_DIR / "data"

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    analysis_server_url: str = "http://localhost:80/api/ingest"
    store_local: bool = True

    class Config:
        env_file = ".env"

settings = Settings()

