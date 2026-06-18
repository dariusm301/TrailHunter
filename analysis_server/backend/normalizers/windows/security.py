from ..base import BaseNormalizer
from models.events import *
from .services.parse_xml_security import _extract_task_details


class SecurityNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent:
        event_id = raw.get('event_id')
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 4624 — An account was successfully logged on
    # ─────────────────────────────────────────────
    def _parse_4624(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})
        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="account_logged_on",
                category="authentication",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=1,
                original=raw.get('message', '').encode('utf-8'),
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('TargetUserName')),
                domain=self._normalize_domain(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetUserSid')),
            ),
            host=HostFields(
                name=self._normalize_hostname(ed.get('WorkstationName')),
            ),
            source=SourceFields(
                ip=self._normalize_ip(ed.get('IpAddress')),
                port=self._normalize_port(ed.get('IpPort')),
            ),
            process=ProcessFields(
                pid=self._hex_to_int(ed.get('ProcessId')),
                executable=self._normalize_executable(ed.get('ProcessName')),
                name=self._normalize_process_name(ed.get('ProcessName')),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            ),
            logon=LogonFields(
                id=self._normalize_logon_id(ed.get('TargetLogonId')),
                type=self._clean(ed.get('LogonType')),
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4625 — An account failed to log on
    # ─────────────────────────────────────────────
    def _parse_4625(self, raw: dict) -> NormalizedEvent:
        pass

    # ─────────────────────────────────────────────
    # Event 4688 — A new process has been created
    # ─────────────────────────────────────────────
    def _parse_4688(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})

        cmd_line = self._normalize_command_line(ed.get('CommandLine'))
        cmd_args = self._parse_command_line_args(cmd_line)

        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="process_created",
                category="process",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=1,
                original=raw.get('message', '').encode('utf-8'),
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('SubjectUserName')),
                domain=self._normalize_domain(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid')),
            ),
            process=ProcessFields(
                pid=self._hex_to_int(ed.get('NewProcessId')),
                executable=self._normalize_executable(ed.get('NewProcessName')),
                name=self._normalize_process_name(ed.get('NewProcessName')),
                command_line=cmd_line,
                args=cmd_args,
                args_count=len(cmd_args) if cmd_args else 0,
                parent=ProcessFields(
                    pid=self._hex_to_int(ed.get('ProcessId')),
                    executable=self._normalize_executable(ed.get('ParentProcessName')),
                    name=self._normalize_process_name(ed.get('ParentProcessName')),
                ),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4702 — A scheduled task was updated
    # ─────────────────────────────────────────────
    def _parse_4702(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})
        task_name = self._clean(ed.get('TaskName'))
        task_details = _extract_task_details(ed.get('TaskContentNew'))
        executable = task_details["command"] or task_details["com_class"]
        process_args = self._normalize_args(
            task_details["arguments"].split() if task_details["arguments"] else None
        )

        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="scheduled_task_updated",
                category="persistence",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=1,
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('SubjectUserName')),
                domain=self._normalize_domain(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid')),
            ),
            host=HostFields(
                hostname=self._normalize_hostname(ed.get('FQDN')),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get('ClientProcessId')),
                executable=self._normalize_executable(executable),
                args=process_args,
                command_line=self._normalize_command_line(task_name),
                parent=ProcessFields(
                    pid=self._normalize_pid(ed.get('ParentProcessId')),
                ),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4698 — A scheduled task was created
    # ─────────────────────────────────────────────
    def _parse_4698(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})
        task_name = self._clean(ed.get('TaskName'))
        task_details = _extract_task_details(ed.get('TaskContent'))
        executable = task_details["command"]
        process_args = self._normalize_args(
            task_details["arguments"].split() if task_details["arguments"] else None
        )
        uses_com_handler = task_details["com_class"] is not None

        full_command = executable
        if process_args:
            full_command = f"{executable} {' '.join(process_args)}"

        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="scheduled_task_created",
                category="persistence",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('SubjectUserName')),
                domain=self._normalize_domain(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid')),
            ),
            host=HostFields(
                hostname=self._normalize_hostname(ed.get('FQDN')),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get('ClientProcessId')),
                executable=self._normalize_executable(executable),
                args=process_args,
                command_line=self._normalize_command_line(full_command),
                parent=ProcessFields(
                    pid=self._normalize_pid(ed.get('ParentProcessId')),
                ),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
                extra={
                    "task_name": self._normalize_task_name(task_name),
                    "uses_com_handler": uses_com_handler,
                    "com_class": self._clean(task_details["com_class"]),
                    "command": self._clean(full_command),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4720 — A user account was created
    # ─────────────────────────────────────────────
    def _parse_4720(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})
        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="user_account_created",
                category="iam",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=3,
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('TargetUserName')),
                domain=self._normalize_domain(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetSid')),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4732 — A member was added to a security-enabled local group
    # ─────────────────────────────────────────────
    def _parse_4732(self, raw: dict) -> NormalizedEvent:
        ed = raw.get('event_data', {})
        group_name = self._clean(ed.get('TargetUserName'))

        return NormalizedEvent(
            timestamp=self._parse_time(raw.get('time_created')),
            event=EventFields(
                action="user_added_to_group",
                category="iam",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get('SubjectUserName')),
                domain=self._normalize_domain(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid')),
            ),
            group=GroupFields(
                name=group_name,
                domain=self._normalize_domain(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetSid')),
                member_id=self._clean(ed.get('MemberSid')),
                member_name=self._clean(ed.get('MemberName')),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            ),
        )