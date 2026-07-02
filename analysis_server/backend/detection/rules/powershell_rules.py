from __future__ import annotations
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import defaultdict

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)

from ..helpers import (
    _action, _ts, _script_block_id, _script_text, _runspace_id, _hostname)

_SUSPICIOUS_PS_PATTERNS = re.compile(
    r"(invoke-expression|iex\s*[\(\$]"
    r"|invoke-webrequest|downloadstring|downloadfile"
    r"|net\.webclient"
    r"|frombase64string|[Cc]onvert::[Ff]rom[Bb]ase64"
    r"|-encodedcommand|-enc\s"
    r"|add-mppreference\s+-exclusion"
    r"|set-mppreference.*disablerealtimemonitoring"
    r"|invoke-mimikatz|sekurlsa|lsadump"
    r"|new-object\s+system\.net\.sockets"
    r"|\$env:temp.*\.exe"
    r"|start-process.*hidden"
    r"|-windowstyle\s+hidden|-w\s+hidden)",
    re.IGNORECASE,
)

_BURST_WINDOW_SECONDS = 30
_BURST_MIN_BLOCKS     = 10



class OrphanedScriptBlockRule(AggregateRule):
    rule_id = "PS_ORPHANED_SCRIPTBLOCK_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        started:   dict[str, tuple[int, NormalizedEvent]] = {}
        completed: set[str] = set()

        for i, e in enumerate(events):
            sb_id = _script_block_id(e)
            if not sb_id:
                continue
            if _action(e) == "scriptblock-started":
                started[sb_id] = (i, e)
            elif _action(e) == "scriptblock-completed":
                completed.add(sb_id)

        findings = []
        for sb_id, (i, e) in started.items():
            if sb_id in completed:
                continue
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Orphaned Script Block — No Completion Event",
                rule_type="aggregate",
                severity=Severity.MEDIUM,
                confidence=0.70,
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic=MitreTactic.DEFENSE_EVASION,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["powershell", "scriptblock", "terminated"],
                source="powershell",
                description=f"ScriptBlock {sb_id[:8]}… started but never completed — possible forced termination",
                timestamp=_ts(e),
                triggered_by=[e.id],
                extra={
                    "script_block_id": sb_id,
                    "runspace_id": _runspace_id(e),
                    "hostname": _hostname(e),
                }
            ))

        return findings


class ConfirmedSuspiciousExecutionRule(AggregateRule):
    rule_id = "PS_CONFIRMED_SUSPICIOUS_EXEC_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        logged:  dict[str, tuple[str, NormalizedEvent]] = {}
        started: dict[str, tuple[str, NormalizedEvent]] = {}

        for i, e in enumerate(events):
            sb_id = _script_block_id(e)
            if not sb_id:
                continue
            if _action(e) == "scriptblock-logged":
                text = _script_text(e)
                if text and _SUSPICIOUS_PS_PATTERNS.search(text):
                    logged[sb_id] = (e.id, e)
            elif _action(e) == "scriptblock-started":
                started[sb_id] = (e.id, e)

        findings = []
        for sb_id, (log_id, log_event) in logged.items():
            if sb_id not in started:
                continue

            start_id, _ = started[sb_id][0]
            text    = _script_text(log_event)
            matched = [m.group() for m in _SUSPICIOUS_PS_PATTERNS.finditer(text)]

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Confirmed Suspicious Script Block Execution",
                rule_type="aggregate",
                severity=Severity.CRITICAL,
                confidence=0.93,
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic=MitreTactic.EXECUTION,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["powershell", "scriptblock", "confirmed", "execution"],
                source="powershell",
                description=(
                    f"Suspicious script block {sb_id[:8]}… confirmed executed "
                    f"(4104+4105 correlation). Patterns: {matched[:3]}"
                ),
                timestamp=_ts(log_event),
                triggered_by=[log_id, start_id],
                event_count=2,
                extra={
                    "script_block_id": sb_id,
                    "runspace_id": _runspace_id(log_event),
                    "matched_patterns": matched,
                    "text_preview": text[:300],
                }
            ))

        return findings



def get_powershell_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
    ]
    aggregate = [
        OrphanedScriptBlockRule(),
        ConfirmedSuspiciousExecutionRule(),
    ]
    return per_event, aggregate