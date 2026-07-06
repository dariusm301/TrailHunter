from __future__ import annotations
from collections import defaultdict
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    Capability, DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)
from ..helpers import _event_id, _ts, _username, _group_name

_GENERIC_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}

_PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "backup operators", "remote desktop users",
}

def _logon_type(event: NormalizedEvent) -> Optional[int]:
    if event.logon and event.logon.type is not None:
        raw = event.logon.type
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None
    return None



class UserCreatedRule(PerEventRule):
    rule_id = "WIN_USER_CREATED_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.event and event.event.action == "user_account_created"):
            return None

        username = _username(event)
        sid = event.user.id if event.user else None

        requires = []
        if username:
            requires = [Capability("local_account_created", bind=("username",),
                                   values=(username,))]

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Account Created",
            rule_type="per_event",
            requires=requires,
            provides=[Capability("account_created", bind=("user_sid",), values=(sid,))],
            severity=Severity.HIGH,
            confidence=0.95,
            technique_id="T1136.001",
            technique_name="Create Account: Local Account",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["account", "persistence"],
            source="windows_events",
            description=f"New account created: '{username}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "created_user": username,
                "domain": event.user.domain if event.user else None,
                "user_sid": sid,
            }
        )


class UserAddedToGroupRule(PerEventRule):
    rule_id = "WIN_GROUP_ADD_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.group:
            return None

        group = _group_name(event)
        if group not in _PRIVILEGED_GROUPS:
            return None

        member_sid = event.group.member_id if event.group else None
        requires = []
        provides = []
        if member_sid:
            requires = [Capability("account_created", bind=("user_sid",), values=(member_sid,))]
            provides = [Capability("account_privileged", bind=("user_sid",), values=(member_sid,))]

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Added to Privileged Group",
            rule_type="per_event",
            requires=requires,
            provides=provides,
            severity=Severity.HIGH,
            confidence=0.97,
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic=MitreTactic.PRIVILEGE_ESCALATION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["privilege_escalation", "account"],
            source="windows_events",
            description=f"User added to privileged group '{group}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "group_name": group,
                "member_sid": member_sid,
            }
        )


class RemoteLoginRule(PerEventRule):
    rule_id = "WIN_REMOTE_LOGIN_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.user:
            return None

        logon_type = _logon_type(event)
        if logon_type not in (3, 8, 10):
            return None

        sid = event.user.id if event.user else None
        if sid in _GENERIC_SIDS:
            return None

        logon_id = event.logon.id if event.logon else None
        username = _username(event)

        requires = []
        if sid:
            requires = [Capability("account_privileged", bind=("user_sid",), values=(sid,))]

        provides = []
        if logon_id:
            provides = [Capability("session_established", bind=("logon.id",), values=(logon_id,),)]

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Remote Interactive Logon",
            rule_type="per_event",
            requires=requires,
            provides=provides,
            fusion_key=[],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1021",
            technique_name="Remote Services",
            tactic=MitreTactic.LATERAL_MOVEMENT,
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            tags=["remote_logon", "lateral_movement", "valid_accounts"],
            source="windows_events",
            description=f"Remote logon by '{username}' — possible attacker-created account",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "logon_user": username,
                "user_sid": sid,
                "source_ip": event.source.ip if event.source else None,
                "logon_type": logon_type,
            }
        )


class BruteForceLoginRule(AggregateRule):
    rule_id = "WIN_BRUTE_FORCE_001"
    THRESHOLD = 5

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for e in events:
            if _event_id(e) != 4625:
                continue
            user = _username(e) or "unknown"
            if not user or user in ("-", ""):  
                continue
            by_user[user].append(e)

        for user, hits in by_user.items():
            if len(hits) < self.THRESHOLD:
                continue

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Brute Force Login Attempt",
                rule_type="aggregate",
                severity=Severity.HIGH,
                confidence=0.90,
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["bruteforce", "authentication"],
                source="windows_events",
                description=f"{len(hits)} failed login attempts for '{user}'",
                timestamp=_ts(hits[0]),
                triggered_by=[e.id for e in hits],
                event_count=len(hits),
                extra={"target_user": user}
            ))

        return findings

def get_auth_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        UserCreatedRule(),
        UserAddedToGroupRule(),
        RemoteLoginRule(),
    ]
    aggregate = [
        BruteForceLoginRule(),
    ]
    return per_event, aggregate