

import json
import logging
import sys
from pathlib import Path

CONFIG_PATH = Path("/home/probe1/TrailHunter/probe/probe_config.json")  
HID_DIR = Path("/home/probe1/TrailHunter/probe/hid")

log = logging.getLogger(__name__)

sys.path.insert(0, str(HID_DIR))


def load_config(path: Path) -> dict:
    if not path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON in config: %s", e)
        sys.exit(1)


def main():
    config = load_config(CONFIG_PATH)

    armed = config.get("armed", False)
    fired = config.get("fired", True)
    if armed:
        log.info("Probe is ARMED -> starting collection flow")

        analysis_server_url = config.get("analysis_server_url")
        time_range = config.get("time_range")
        token = config.get("probe_token")

        try:
            from hid_collector import trigger_collection
        except ImportError as e:
            log.error("Failed to import hid_collector: %s", e)
            sys.exit(1)

        trigger_collection(
            analysis_server_url=analysis_server_url,
            time_range=time_range,
            token=token,
        )

    else:
        log.info("Probe is NOT armed -> starting config socket flow")

        try:
            from hid_config import trigger_client_socket
        except ImportError as e:
            log.error("Failed to import hid_config: %s", e)
            sys.exit(1)

        trigger_client_socket()


if __name__ == "__main__":
    main()
