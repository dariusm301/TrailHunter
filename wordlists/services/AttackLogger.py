
import json
import os
from datetime import datetime, timezone
from typing import Any


MITRE = {
    "port_scan":          {"id": "T1046",     "name": "Network Service Discovery"},
    "web_recon":          {"id": "T1595.003", "name": "Wordlist Scanning"},
    "brute_force":        {"id": "T1110.001", "name": "Password Guessing"},
    "file_upload":        {"id": "T1505.003", "name": "Web Shell"},
    "command_exec":       {"id": "T1059.001", "name": "PowerShell / Command Execution"},
    "create_user":        {"id": "T1136.001", "name": "Create Local Account"},
    "av_exclusion":       {"id": "T1562.001", "name": "Disable or Modify Tools"},
    "malware_upload":     {"id": "T1105",     "name": "Ingress Tool Transfer"},
    "registry_persist":   {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
    "scheduled_task":     {"id": "T1053.005", "name": "Scheduled Task"},
    "data_exfiltration":  {"id": "T1041",     "name": "Exfiltration Over C2 Channel"},
    "interactive_shell":  {"id": "T1059",     "name": "Command and Scripting Interpreter"},
    "lateral_movement":   {"id": "T1021.006", "name": "Remote Services: WinRM"},
}

# Event ID-uri Windows așteptate per tehnică
EXPECTED_EVENTS = {
    "port_scan":         [],
    "web_recon":         [],
    "brute_force":       [4625, 4771],
    "file_upload":       [],
    "command_exec":      [4688, 4103, 4104],
    "create_user":       [4720, 4732, 4728],
    "av_exclusion":      [4688, 5001],
    "malware_upload":    [4688, 5156],
    "registry_persist":  [4657, 13],
    "scheduled_task":    [4698, 4702, 106],
    "data_exfiltration": [4688, 5156, 3],
    "interactive_shell": [4688, 4103],
    "lateral_movement":  [4624, 4648],
}


class AttackLogger:
    def __init__(self, output_dir: str = "attack_logs"):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(output_dir, f"attack_{ts}.jsonl")
        self.session_id = ts
        self._open()
        self.log("session_start", "meta", action="attack_session_start", details={
            "log_file": self.log_path,
            "note": "Ground truth log pentru validare TrailHunter"
        })

    def _open(self):
        self._fh = open(self.log_path, "a", encoding="utf-8")

    def _write(self, entry: dict):
        self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._fh.flush()

    def log(
        self,
        technique_key: str,
        phase: str,
        action: str,
        details: dict[str, Any] | None = None,
        result: Any = None,
        success: bool | None = None,
    ) -> dict:
        mitre = MITRE.get(technique_key, {"id": "T0000", "name": "Unknown"})
        entry = {
            "@timestamp":      datetime.now(timezone.utc).isoformat(),
            "session_id":      self.session_id,
            "phase":           phase,
            "technique":       mitre["id"],
            "technique_name":  mitre["name"],
            "action":          action,
            "details":         details or {},
            "result":          str(result)[:500] if result is not None else None,
            "success":         success,
            "expected_events": EXPECTED_EVENTS.get(technique_key, []),
        }
        self._write(entry)
        _fmt = f"[{entry['@timestamp']}] [{phase.upper():12}] {mitre['id']} | {action}"
        if success is True:
            _fmt += "\nSUCCESS"
        elif success is False:
            _fmt += "\nFAILED"
        print(_fmt)
        return entry

    def close(self):
        self.log("session_start", "meta", action="attack_session_end", details={
            "log_file": self.log_path
        })
        self._fh.close()
        print(f"\n[AttackLogger] Log salvat în: {self.log_path}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()