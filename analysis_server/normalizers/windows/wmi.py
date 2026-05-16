from ..base import BaseNormalizer
from models.events import *
import re
from .services.convert_sid import convert_raw_sid_to_string



class WMINormalizer(BaseNormalizer):
    
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get('event_id')
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)
    
    def _parse_5858(self, raw: dict) -> NormalizedEvent:

        """
        Example message:
            {  
                "event_id": 5858,
                "message": "Id = {00000000-0000-0000-0000-000000000000}; ClientMachine = SERVER; User = NT AUTHORITY\\NETWORK SERVICE; ClientProcessId = 11012; Component = Unknown; Operation = Start IWbemServices::ExecQuery - ROOT\\StandardCimv2 : SELECT * FROM MSFT_NetAdapterStatisticsSettingData WHERE Name = 'Ethernet'; ResultCode = 0x80041032; PossibleCause = Unknown",
                "time_created": "2026-03-28T00:54:47Z"
            }   
        """
        kv = self.parse_kv(raw.get('message', ''))
        domain, user = self._parse_user(kv.get("User", ""))
        pid_raw = kv.get("ClientProcessId", "0")
        pid = int(pid_raw) if pid_raw.isdigit() else None

        return NormalizedEvent(
            event=EventFields(
                action="wmi_query_error",
                category="configuration",
                code=str(raw.get("event_id")),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows.wmi",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-WMI-Activity",
                severity=1,
                module="windows",
            ),
            host=HostFields(
                hostname=kv.get("ClientMachine")
            ),
            user=UserFields(
                name=user,
                domain=domain
            ),
            process=ProcessFields(
                pid=pid,
                name=None
            ),
            winlogs=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
                computer_name=kv.get("ClientMachine")
            )
    )

    def _parse_5857(self, raw: dict) -> NormalizedEvent:
        """Example message:
        {
            'event_id': 5857, 
            'message': 'Win32_DeviceGuard provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 9724; ProviderPath = %SystemRoot%\\System32\\Win32_DeviceGuard.dll', 
            'time_created': '2026-03-28T00:55:56Z'
        }
        """
        id = str(raw.get('event_id'))
        time_created = self._parse_time(raw.get('time_created'))

        message = raw.get('message', '')
        sentence, _, kv_part = message.partition(".")
        kv = self.parse_kv(kv_part)
        provider_match = re.match(r"^(.+?) provider started with result code (0x[0-9a-fA-F]+)", sentence)
        provider_name = provider_match.group(1) if provider_match else None
        result_code = provider_match.group(2) if provider_match else None

        pid_raw = kv.get("ProcessID", "")
        pid=int(pid_raw) if pid_raw.isdigit() else None
        return NormalizedEvent(
            event=EventFields(
                action="wmi_provider_start",
                category="configuration",
                code=id,
                created=time_created,
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=message.encode("utf-8"),
                provider=provider_name,
            ),
            process=ProcessFields(
                name=kv.get("HostProcess"),
                pid=pid,
                executable=kv.get("ProviderPath")
            ),
            winlogs=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
            )
        )
    
    def _parse_5859(self, raw: dict) -> NormalizedEvent:
        """
            Example message:
            {
                'event_id': 5859, 
                'message': 'Namespace = //./root/CIMV2; NotificationQuery = select * from MSFT_SCMEventLogEvent; OwnerName = S-1-5-32-544; HostProcessID = 3564;  Provider= SCM Event Provider, queryID = 0; PossibleCause = Permanent', 
                'time_created': '2026-03-28T00:55:44Z'
            }
        """
        id = str(raw.get('event_id'))
        time_created = self._parse_time(raw.get('time_created'))
        kv = self.parse_kv(raw.get('message', ''))
        provider_raw = kv.get("Provider", "")
        provider_name = provider_raw.split(",")[0].strip() if provider_raw else None

        pid_raw = kv.get("HostProcessID", "")
        pid=int(pid_raw) if pid_raw.isdigit() else None

        return NormalizedEvent(
            event=EventFields(
                provider=provider_name,
                action="wmi_notification_query",
                category="configuration",
                code=id,
                created=time_created,
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
            ),
            process=ProcessFields(
                pid=pid,
            ),
            user=UserFields(
                id=kv.get("OwnerName")
            ),
            winlogs=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
            )
        )
    
    def _parse_5860(self, raw: dict) -> NormalizedEvent:
        """
        Example message:
        {
            'event_id': 5860, 
            'message': "Namespace = ROOT\\Subscription; NotificationQuery = SELECT * FROM __InstanceOperationEvent WITHIN 5WHERE TargetInstance ISA '__EventConsumer' OR TargetInstance ISA '__EventFilter' OR TargetInstance ISA '__FilterToConsumerBinding'; UserName = NT AUTHORITY\\SYSTEM; ClientProcessID = 4196, ClientMachine = SERVER; PossibleCause = Temporary", 
            'time_created': '2026-03-28T00:55:44Z'
        }
        """
        id = str(raw.get('event_id'))
        time_created = self._parse_time(raw.get('time_created'))
        kv = self.parse_kv(raw.get('message', ''))
        provider_name = "WMI Subscription"

        pid_match = re.search(r'ClientProcessID\s*=\s*(\d+)', raw.get('message', ''))
        pid = int(pid_match.group(1)) if pid_match else None
        host_match = re.search(r'ClientMachine\s*=\s*([^;]+)', raw.get('message', ''))
        hostname = host_match.group(1).strip() if host_match else None

        domain, user = self._parse_user(kv.get("UserName", ""))

        return NormalizedEvent(
            event=EventFields(
                provider=provider_name,
                action="wmi_subscription_query",
                category="configuration",
                code=id,
                created=time_created,
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
            ),
            host=HostFields(
                hostname=hostname
            ),
            process=ProcessFields(
                pid=pid,
            ),
            user=UserFields(
                name=user,
                domain=domain
            ),
            winlogs=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
                computer_name=hostname
            )
        )
    
    def _parse_5861(self, raw: dict) -> NormalizedEvent:
        """
        Example message:
        {
            'event_id': 5861, 
            'message': 'Namespace = //./root/subscription; Eventfilter = SCM Event Log Filter (refer to its activate eventid:5859); Consumer = NTEventLogEventConsumer="SCM Event Log Consumer"; PossibleCause = Binding EventFilter: \ninstance of __EventFilter\n{\n\tCreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};\n\tEventNamespace = "root\\\\cimv2";\n\tName = "SCM Event Log Filter";\n\tQuery = "select * from MSFT_SCMEventLogEvent";\n\tQueryLanguage = "WQL";\n};\nPerm. Consumer: \ninstance of NTEventLogEventConsumer\n{\n\tCategory = 0;\n\tCreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};\n\tEventType = 1;\n\tName = "SCM Event Log Consumer";\n\tNameOfUserSIDProperty = "sid";\n\tSourceName = "Service Control Manager";\n};\n',
            'time_created': '2026-03-28T00:55:44Z'
        }
        """
        id = str(raw.get('event_id'))
        time_created = self._parse_time(raw.get('time_created'))
        kv = self.parse_kv(raw.get('message', ''))

        entity_search = re.search(r'="?([^"]+)"?', kv.get('Consumer', ''))
        entity = entity_search.group(1).strip() if entity_search else None

        process_name_search = re.search(r'([^=]+)', kv.get('Consumer', ''))
        name = process_name_search.group(1).strip() if process_name_search else None

        sid_search = re.search(r'CreatorSID\s*=\s*{([^}]+)}', kv.get('PossibleCause', ''))
        sid_raw = sid_search.group(1).strip() if sid_search else None
        sid = convert_raw_sid_to_string([int(x.strip()) for x in sid_raw.strip().split(",")]) if sid_raw else None

        query = kv.get('Query', '').strip('"')

        return NormalizedEvent(
            event=EventFields(
                provider="WMI Event Log Binding",
                action="wmi_event_subscription_created",
                category="persistence", 
                code=id,
                created=time_created,
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get('message', '').encode('utf-8')
            ),
            user=UserFields(
                id=sid
            ),
            process=ProcessFields(
                name=name,
                entity_id=entity
            ),
            winlogs=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
            )
        )


