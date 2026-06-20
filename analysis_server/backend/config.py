import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
BASE_DIR = Path(__file__).parent
COLLECTOR_DIR = BASE_DIR.parent / "collector"
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 80
    secret_key: str = os.getenv("TRAILHUNTER_SECRET_KEY")
    algorithm: str = "HS256"

    access_token_expire_minutes: int = 15
    refresh_token_expire_days : int = 7
    refresh_cookie_name : str = "refresh_token"

    class Config:
        env_file = ".env"
        env_prefix = "TRAILHUNTER_"

settings = Settings()

