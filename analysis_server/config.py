from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).parent
COLLECTOR_DIR = BASE_DIR.parent / "collector"
DATA_DIR = BASE_DIR / "data"

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 80
    store_local: bool = True

    class Config:
        env_file = ".env"

settings = Settings()

