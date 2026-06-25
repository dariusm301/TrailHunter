from ..base import BaseNormalizer
from models.events import *


class SysmonNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get("event_id")
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        event = parser(raw)
        if event and not event.host:
            hostname = self._extract_hostname(raw)
            if hostname:
                event.host = HostFields(name=hostname)
        return event

    # ─────────────────────────────────────────────
    # Event 1 — Process Create
    # ─────────────────────────────────────────────
    def _parse_1(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        cmd = ed.get("CommandLine", "")
        args = cmd.split()[1:] if cmd else []
        image = ed.get("Image", "")
        username, domain = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action="process_created",
                category="process",
                code="1",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),       # era _normalize_hostname — fix
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(image),
                name=self._normalize_process_name(image),
                command_line=self._normalize_command_line(cmd),
                args=self._normalize_args(args),
                args_count=len(args) if args else None,
                hash_sha256=self._clean(ed.get("Hashes")),
                entity_id=self._clean(ed.get("ProcessGuid")),
                parent=ProcessFields(
                    pid=self._normalize_pid(ed.get("ParentProcessId")),
                    executable=self._normalize_executable(ed.get("ParentImage")),
                    name=self._normalize_process_name(ed.get("ParentImage")),
                    command_line=self._normalize_command_line(ed.get("ParentCommandLine")),
                    entity_id=self._clean(ed.get("ParentProcessGuid"))
                ),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=1,
                provider_name="Microsoft-Windows-Sysmon",
            ),
            logon=LogonFields(
                id=self._normalize_logon_id(ed.get("LogonId")),
            ),
        )

    # ─────────────────────────────────────────────
    # Event 3 — Network Connection
    # ─────────────────────────────────────────────
    def _parse_3(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, domain = self._extract_username_and_domain(ed.get("User", ""))
        initiated = ed.get("Initiated", "").lower() == "true"

        return NormalizedEvent(
            timestamp=self._parse_time(raw.get("time_created")),
            event=EventFields(
                action="network_connection",
                category="network",
                code="3",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            network=NetworkFields(
                transport=self._clean(ed.get("Protocol")),
                direction="egress" if initiated else "ingress",
            ),
            source=SourceFields(
                ip=self._normalize_ip(ed.get("SourceIp")),
                port=self._normalize_port(ed.get("SourcePort")),
            ),
            destination=DestinationFields(
                ip=self._normalize_ip(ed.get("DestinationIp")),
                port=self._normalize_port(ed.get("DestinationPort")),
                domain=self._normalize_hostname(ed.get("DestinationHostname")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=3,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 5 — Process Terminated
    # ─────────────────────────────────────────────
    def _parse_5(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="process_terminated",
                category="process",
                code="5",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=5,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 7 — Image Loaded (DLL)
    # ─────────────────────────────────────────────
    def _parse_7(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, _ = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action="image_loaded",
                category="library",
                code="7",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            file=FileFields(                                  
                path=self._clean(ed.get("ImageLoaded")),
                name=self._normalize_filename(ed.get("ImageLoaded")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=7,
                provider_name="Microsoft-Windows-Sysmon",
                extra={
                    "hashes": self._clean(ed.get("Hashes")),
                    "signature_status": self._clean(ed.get("SignatureStatus")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 8 — CreateRemoteThread
    # ─────────────────────────────────────────────
    def _parse_8(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, _ = self._extract_username_and_domain(ed.get("SourceUser", ""))

        return NormalizedEvent(
            event=EventFields(
                action="create_remote_thread",
                category="process",
                code="8",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=4, 
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("SourceProcessId")),
                executable=self._normalize_executable(ed.get("SourceImage")),
                name=self._normalize_process_name(ed.get("SourceImage")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            target=TargetFields(
                process=ProcessFields(
                    pid=self._normalize_pid(ed.get("TargetProcessId")),
                    executable=self._normalize_executable(ed.get("TargetImage")),
                    name=self._normalize_process_name(ed.get("TargetImage")),
                )
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=8,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    
    # ─────────────────────────────────────────────
    # Event 10 — Process Access
    # ─────────────────────────────────────────────
    def _parse_10(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        severity = 5 if "lsass" in ed.get("TargetImage", "").lower() else 3
        username, domain = self._extract_username_and_domain(ed.get("SourceUser", ""))

        return NormalizedEvent(
            event=EventFields(
                action="process_access",
                category="process",
                code="10",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("SourceProcessId")),
                executable=self._normalize_executable(ed.get("SourceImage")),
                name=self._normalize_process_name(ed.get("SourceImage")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            target=TargetFields(
                process=ProcessFields(
                    pid=self._normalize_pid(ed.get("TargetProcessId")),
                    executable=self._normalize_executable(ed.get("TargetImage")),
                    name=self._normalize_process_name(ed.get("TargetImage")),
                ),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=10,
                provider_name="Microsoft-Windows-Sysmon",
                extra={
                    "granted_access": self._clean(ed.get("GrantedAccess")),
                    "call_trace": self._clean(ed.get("CallTrace")),
                    "source_thread_id": self._clean(ed.get("SourceThreadId")),
                    "target_user": self._clean(ed.get("TargetUser")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 11 — File Create
    # ─────────────────────────────────────────────
    def _parse_11(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, domain = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action="file_created",
                category="file",
                code="11",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
                parent=ProcessFields(
                    pid=self._normalize_pid(ed.get("ParentProcessId")),
                    executable=self._normalize_executable(ed.get("ParentImage")),
                    name=self._normalize_process_name(ed.get("ParentImage")),
                    entity_id=self._clean(ed.get("ParentProcessGuid"))
                )
            ),
            file=FileFields(
                path=self._clean(ed.get("TargetFilename")),
                name=self._normalize_filename(ed.get("TargetFilename")),
                created=self._parse_time(ed.get("CreationUtcTime")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=11,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 12/13 — Registry Add/Set
    # ─────────────────────────────────────────────
    def _parse_12(self, raw: dict) -> NormalizedEvent:
        return self._parse_registry(raw, event_id=12, action="registry_key_created")

    def _parse_13(self, raw: dict) -> NormalizedEvent:
        return self._parse_registry(raw, event_id=13, action="registry_value_set")

    def _parse_registry(self, raw: dict, event_id: int, action: str) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, domain = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action=action,
                category="registry",
                code=str(event_id),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            registry=RegistryFields(
                path=self._clean(ed.get("TargetObject")),
                value=self._clean(ed.get("Details"))
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=event_id,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 22 — DNS Query
    # ─────────────────────────────────────────────
    def _parse_22(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        username, domain = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action="dns_query",
                category="network",
                code="22",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            dns=DNSFields(
                question=DNSQuestionFields(
                    name=self._normalize_hostname(ed.get("QueryName")),
                    type="A",
                ),
                answers=self._parse_dns_answers(ed.get("QueryResults")),
                response_code=self._normalize_response_code(ed.get("QueryStatus")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=22,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 17/18 — Pipe Created / Connected
    # ─────────────────────────────────────────────
    def _parse_17(self, raw: dict) -> NormalizedEvent:
        return self._parse_pipe(raw, event_id=17, action="pipe_created")

    def _parse_18(self, raw: dict) -> NormalizedEvent:
        return self._parse_pipe(raw, event_id=18, action="pipe_connected")

    def _parse_pipe(self, raw: dict, event_id: int, action: str) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        pipe_name = self._normalize_hostname(ed.get("PipeName", "")) or ""

        SUSPICIOUS_PIPES = {
            "\\postex_",     # Cobalt Strike post-ex
            "\\msagent_",    # Cobalt Strike
            "mojo.5688.",    # Chrome / injectie
            "\\isapi_http",  # Cobalt Strike
            "\\isapi_dg",    # Cobalt Strike
            "\\wkssvc_",
            "\\ntsvcs",
            "\\scerpc_",
            "\\mepipe",
            "\\meterpreter",  # Metasploit
            "\\psexec",       # PsExec / lateral movement
            "\\paexec",
            "\\remcom",
        }
        is_suspicious = any(pattern in pipe_name for pattern in SUSPICIOUS_PIPES)
        severity = 5 if is_suspicious else 2
        username, domain = self._extract_username_and_domain(ed.get("User", ""))

        return NormalizedEvent(
            event=EventFields(
                action=action,
                category="ipc",
                code=str(event_id),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(ed.get("ProcessId")),
                executable=self._normalize_executable(ed.get("Image")),
                name=self._normalize_process_name(ed.get("Image")),
                entity_id=self._clean(ed.get("ProcessGuid")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=event_id,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )