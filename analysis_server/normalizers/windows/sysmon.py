from ..base import BaseNormalizer
from models.events import *


class SysmonNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get("event_id")
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 1 — Process Create
    # ─────────────────────────────────────────────
    def _parse_1(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        cmd = ed.get("CommandLine", "")
        args = cmd.split()[1:] if cmd else []

        return NormalizedEvent(
            event=EventFields(
                action="process_created",
                category="process",
                type="start",
                code="1",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
                domain=self._clean(ed.get("User", "").split("\\")[0] if "\\" in ed.get("User", "") else None),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
                command_line=cmd or None,
                args=args or None,
                args_count=len(args) or None,
                working_directory=ed.get("CurrentDirectory"),
                hash=ed.get("Hashes"),
                parent=ProcessFields(
                    pid=int(ed.get("ParentProcessId")) if self._clean(ed.get("ParentProcessId")) else None,
                    executable=ed.get("ParentImage"),
                    name=ed.get("ParentImage", "").split("\\")[-1] or None,
                    command_line=ed.get("ParentCommandLine"),
                ),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=1,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 3 — Network Connection
    # ─────────────────────────────────────────────
    def _parse_3(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        dst_port, src_port = None, None
        try:
            dst_port = int(ed.get("DestinationPort")) if ed.get("DestinationPort") else None
            src_port = int(ed.get("SourcePort")) if ed.get("SourcePort") else None
        except ValueError:
            pass

        return NormalizedEvent(
            event=EventFields(
                action="network_connection",
                category="network",
                type="connection",
                code="3",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
                domain=self._clean(ed.get("User", "").split("\\")[0] if "\\" in ed.get("User", "") else None),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            source=SourceFields(
                address=self._clean(ed.get("SourceIp")),
                port=src_port,
            ),
            destination=DestinationFields(
                address=self._clean(ed.get("DestinationIp")),
                domain=self._clean(ed.get("DestinationHostname")),
                port=dst_port,
            ),
            network=NetworkFields(
                transport=self._clean(ed.get("Protocol")),
                direction="egress" if ed.get("Initiated") == "true" else "ingress",
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
                type="end",
                code="5",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
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

        return NormalizedEvent(
            event=EventFields(
                action="image_loaded",
                category="library",
                type="load",
                code="7",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            file=FileFields(
                path=ed.get("ImageLoaded"),
                name=ed.get("ImageLoaded", "").split("\\")[-1] or None,
                hash=ed.get("Hashes"),
                code_signature=ed.get("SignatureStatus"),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=7,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 8 — CreateRemoteThread
    # ─────────────────────────────────────────────
    def _parse_8(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="create_remote_thread",
                category="process",
                type="change",
                code="8",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=4,       # ridicat — indicator clar de injectie
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("SourceUser", "").split("\\")[-1]),
            ),
            process=ProcessFields(
                pid=int(ed.get("SourceProcessId")) if self._clean(ed.get("SourceProcessId")) else None,
                executable=ed.get("SourceImage"),
                name=ed.get("SourceImage", "").split("\\")[-1] or None,
               
            ),
            target=TargetFields(
                process=ProcessFields(
                    pid=int(ed.get("TargetProcessId")) if self._clean(ed.get("TargetProcessId")) else None,
                    executable=ed.get("TargetImage"),
                    name=ed.get("TargetImage", "").split("\\")[-1] or None,
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

        # Severitate dinamică: accesul la LSASS e critic, altfel mediu
        target_image = ed.get("TargetImage", "").lower()
        severity = 5 if "lsass" in target_image else 3

        return NormalizedEvent(
            event=EventFields(
                action="process_access",
                category="process",
                type="access",
                code="10",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("SourceUser", "").split("\\")[-1]),
                domain=self._clean(ed.get("SourceUser", "").split("\\")[0] if "\\" in ed.get("SourceUser", "") else None),
            ),
            process=ProcessFields(
                # source = procesul care face accesul
                pid=int(ed.get("SourceProcessId")) if self._clean(ed.get("SourceProcessId")) else None,
                executable=ed.get("SourceImage"),
                name=ed.get("SourceImage", "").split("\\")[-1] or None,
                target=TargetFields(
                    process=ProcessFields(
                        pid=int(ed.get("TargetProcessId")) if self._clean(ed.get("TargetProcessId")) else None,
                        executable=ed.get("TargetImage"),
                        name=ed.get("TargetImage", "").split("\\")[-1] or None,
                    )
                ),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=10,
                provider_name="Microsoft-Windows-Sysmon",
                extra={
                    "granted_access": ed.get("GrantedAccess"),
                    "call_trace": ed.get("CallTrace"),
                    "source_thread_id": ed.get("SourceThreadId"),
                    "target_user": self._clean(ed.get("TargetUser")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 11 — File Create
    # ─────────────────────────────────────────────
    def _parse_11(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="file_created",
                category="file",
                type="creation",
                code="11",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            file=FileFields(
                path=ed.get("TargetFilename"),
                name=ed.get("TargetFilename", "").split("\\")[-1] or None,
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

        target = ed.get("TargetObject", "").lower()
        is_run_key = any(k in target for k in ["\\run\\", "\\runonce\\", "\\run ", "currentversion\\run"])
        severity = 4 if is_run_key else 2

        return NormalizedEvent(
            event=EventFields(
                action=action,
                category="registry",
                type="change",
                code=str(event_id),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            registry=RegistryFields(
                path=ed.get("TargetObject"),
                value=ed.get("Details"),        # prezent la event 13
                event_type=ed.get("EventType"),
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
    @staticmethod
    def _parse_dns_answers(query_results: str | None) -> list[DNSAnswerFields] | None:
        if not query_results:
            return None
        answers = []
        for result in query_results.split(";"):
            result = result.strip()
            if not result:
                continue
            answers.append(
                DNSAnswerFields(
                    data=result,
                    type="A"
                )
            )
        return answers

    def _parse_22(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="dns_query",
                category="network",
                type="lookup",
                code="22",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            dns=DNSFields(
                question=DNSQuestionFields(
                    name=ed.get("QueryName"),
                    type="A"
                ),
                answers=self._parse_dns_answers(ed.get("QueryResults")),
                response_code=ed.get("QueryStatus"),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=22,
                provider_name="Microsoft-Windows-Sysmon",
            ),
        )
    

        
    # ─────────────────────────────────────────────
    # Event 17 — Pipe Created
    # ─────────────────────────────────────────────
    def _parse_17(self, raw: dict) -> NormalizedEvent:
        return self._parse_pipe(raw, event_id=17, action="pipe_created")

    # ─────────────────────────────────────────────
    # Event 18 — Pipe Connected
    # ─────────────────────────────────────────────
    def _parse_18(self, raw: dict) -> NormalizedEvent:
        return self._parse_pipe(raw, event_id=18, action="pipe_connected")

    def _parse_pipe(self, raw: dict, event_id: int, action: str) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        pipe_name = ed.get("PipeName", "").lower()

        # Named pipes cunoscute ca malițioase (C2 frameworks)
        SUSPICIOUS_PIPES = {
            "\\postex_",        # Cobalt Strike post-ex
            "\\msagent_",       # Cobalt Strike
            "mojo.5688.",       # Chrome / injectie
            "\\isapi_http",     # Cobalt Strike
            "\\isapi_dg",       # Cobalt Strike
            "\\wkssvc_",
            "\\ntsvcs",
            "\\scerpc_",
            "\\mepipe",
            "\\meterpreter",    # Metasploit
            "\\psexec",         # PsExec / lateral movement
            "\\paexec",
            "\\remcom",
        }
        is_suspicious = any(pattern in pipe_name for pattern in SUSPICIOUS_PIPES)
        severity = 5 if is_suspicious else 2

        return NormalizedEvent(
            event=EventFields(
                action=action,
                category="ipc",
                type="start" if event_id == 17 else "connection",
                code=str(event_id),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_sysmon",
                module="sysmon",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Sysmon",
            ),
            user=UserFields(
                name=self._clean(ed.get("User", "").split("\\")[-1]),
                domain=self._clean(ed.get("User", "").split("\\")[0] if "\\" in ed.get("User", "") else None),
            ),
            process=ProcessFields(
                pid=int(ed.get("ProcessId")) if self._clean(ed.get("ProcessId")) else None,
                executable=ed.get("Image"),
                name=ed.get("Image", "").split("\\")[-1] or None,
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-Sysmon/Operational",
                event_id=event_id,
                provider_name="Microsoft-Windows-Sysmon",
                extra={
                    "pipe_name": ed.get("PipeName"),
                },
            ),
        )