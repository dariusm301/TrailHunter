from pathlib import Path
from pydantic_settings import BaseSettings
import json

BASE_DIR = Path(__file__).parent
COLLECTOR_DIR = BASE_DIR.parent / "collector"
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "probe_config.json" 

DEFAULT_CONFIG = {
  "token": None,
  "armed": False,
  "wifi": None,
  "analysis_server_url": None,
  "time_range": 48,
  "local_storage": True
}

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


class Config:

    def __init__(self):
        self._config = load_config()

    def get(self) -> dict:
        return self._config

    def save(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = CONFIG_PATH.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(self._config, f, indent=2)
        tmp_path.replace(CONFIG_PATH)

    def update(self, **changes) -> dict:
        self._config.update(changes)
        self.save()
        return self._config

probe_config = Config()
