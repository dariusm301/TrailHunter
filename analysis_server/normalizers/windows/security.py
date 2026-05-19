from ..base import BaseNormalizer
from models.events import *
from .services.parse_xml_security import _extract_task_details

class SecurityNormalizer(BaseNormalizer):
    def normalize(self, raw : dict) -> NormalizedEvent:
        event_id = raw.get('event_id')
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)
    
    
    def _parse_4624(self, raw : dict) -> NormalizedEvent:
        """
        Event ID 4624: An account was successfully logged on. Example:
        {
            'event_id': 4624, 
            'message': 'An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSERVER$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t5\r\n\tRestricted Admin Mode:\t-\r\n\tRemote Credential Guard:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\tLinked Logon ID:\t\t0x0\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x45c\r\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t-\r\n\tSource Port:\t\t-\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tAdvapi  \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.', 
            'event_data': 
            {
                'KeyLength': '0', 
                'SubjectUserSid': 'S-1-5-18', 
                'TargetLinkedLogonId': '0x0', 
                'SubjectLogonId': '0x3e7', 
                'AuthenticationPackageName': 'Negotiate', 
                'TargetOutboundUserName': '-', 
                'ImpersonationLevel': '%%1833', 
                'LogonProcessName': 'Advapi  ', 
                'TargetDomainName': 'NT AUTHORITY', 
                'LmPackageName': '-', 
                'IpAddress': '-', 
                'SubjectDomainName': 'WORKGROUP', 
                'RemoteCredentialGuard': '-', 
                'ProcessName': 'C:\\Windows\\System32\\services.exe', 
                'TransmittedServices': '-', 
                'ProcessId': '0x45c', 
                'SubjectUserName': 'SERVER$', 
                'TargetOutboundDomainName': '-', 
                'TargetLogonId': '0x3e7', 
                'TargetUserName': 'SYSTEM', 
                'RestrictedAdminMode': '-', 
                'LogonGuid': '{00000000-0000-0000-0000-000000000000}', 
                'LogonType': '5', 
                'IpPort': '-', 
                'VirtualAccount': '%%1843', 
                'TargetUserSid': 'S-1-5-18', 
                'ElevatedToken': '%%1842',
                'WorkstationName': '-'
                }, 
                'time_created': '2026-03-29T20:23:12Z'
            }
        """
        ed = raw.get('event_data', {})
        return NormalizedEvent(
            
            event=EventFields(
                action="account_logged_on",
                category="authentication",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=1,
                original=raw.get('message').encode('utf-8')
            ),
            user=UserFields(
                name = self._clean(ed.get('TargetUserName')) ,
                domain = self._clean(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetUserSid'))
            ),
            host=HostFields(
                name = self._clean(ed.get('WorkstationName'))
            ),
            source=SourceFields(
                address = self._clean(ed.get('IpAddress')),
                port = int(ed.get('IpPort')) if self._clean(ed.get('IpPort')) else None
            ),
            process=ProcessFields(
                pid = self._hex_to_int(ed.get('ProcessId')),
                executable= ed.get('ProcessName'),
                name= ed.get('ProcessName').split('\\')[-1] if ed.get('ProcessName') else None,
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing", 
            )
        )

    def _parse_4625(self, raw : dict) -> NormalizedEvent:
        """
            Event ID 4625: An account failed to log on. Example:
            {
                
            }
        """

    def _parse_4688(self, raw : dict) -> NormalizedEvent:
        """
        Event ID 4688: A new process has been created. Example:
        {
            'event_id': 4688, 
            'message': 'A new process has been created.\r\n\r\nCreator Subject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSERVER$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nTarget Subject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\nProcess Information:\r\n\tNew Process ID:\t\t0x2bb0\r\n\tNew Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\tToken Elevation Type:\tTokenElevationTypeDefault (1)\r\n\tMandatory Label:\t\tS-1-16-16384\r\n\tCreator Process ID:\t0x45c\r\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\r\n\tProcess Command Line:\tC:\\WINDOWS\\system32\\svchost.exe -k InvSvcGroup -p -s InventorySvc\r\n\r\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\r\n\r\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\r\n\r\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\r\n\r\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.', ]
            'event_data': {
                'SubjectUserName': 'SERVER$', 
                'CommandLine': 'C:\\WINDOWS\\system32\\svchost.exe -k InvSvcGroup -p -s InventorySvc', 
                'SubjectLogonId': '0x3e7', 
                'SubjectDomainName': 'WORKGROUP', 
                'TargetLogonId': '0x0', 
                'TokenElevationType': '%%1936', 
                'SubjectUserSid': 'S-1-5-18', 
                'NewProcessName': 'C:\\Windows\\System32\\svchost.exe', 
                'NewProcessId': '0x2bb0', 
                'ProcessId': '0x45c', 
                'MandatoryLabel': 'S-1-16-16384', 
                'ParentProcessName': 'C:\\Windows\\System32\\services.exe', 
                'TargetUserSid': 'S-1-0-0', 
                'TargetDomainName': '-', 
                'TargetUserName': '-'
            }, 
            'time_created': '2026-03-29T20:23:12Z'
        }
        """
        ed = raw.get('event_data', {})
        return NormalizedEvent(
            
            event=EventFields(
                action="process_created",
                category="process",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=1,
                original=raw.get('message').encode('utf-8')
            ),
            user=UserFields(
                name = self._clean(ed.get('SubjectUserName')),
                domain = self._clean(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid'))
            ),
            process=ProcessFields(
                pid = self._hex_to_int(ed.get('NewProcessId')),
                executable= ed.get('NewProcessName'),
                name=ed.get('NewProcessName').split('\\')[-1] or None,
                command_line = ed.get('CommandLine'),
                parent=ProcessFields(
                    pid = self._hex_to_int(ed.get('ProcessId')),
                    executable= ed.get('ParentProcessName'),
                    name= ed.get('ParentProcessName').split('\\')[-1] if ed.get('ParentProcessName') else None
                )
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing", 
            )
        )


    def _parse_4702(self, raw: dict) -> NormalizedEvent:
        """
        Event ID 4702: A scheduled task was updated. Example:
        {
            'event_id': 4702, 
            'message': 'A scheduled task was updated.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-20\r\n\tAccount Name:\t\tSERVER$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E4\r\n\r\nTask Information:\r\n\tTask Name: \t\t\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask\r\n\tTask New Content: \t\t<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n  <RegistrationInfo>\r\n    <Source>$(@%systemroot%\\system32\\sppc.dll,-200)</Source>\r\n    <Author>$(@%systemroot%\\system32\\sppc.dll,-200)</Author>\r\n    <Version>1.0</Version>\r\n    <Description>$(@%systemroot%\\system32\\sppc.dll,-201)</Description>\r\n    <URI>\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask</URI>\r\n    <SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-123231216-2592883651-3715271367-3753151631-4175906628)(A;;FR;;;S-1-5-87-2912274048-3994893941-1669128114-1310430903-1263774323)</SecurityDescriptor>\r\n  </RegistrationInfo>\r\n  <Triggers>\r\n    <CalendarTrigger>\r\n      <StartBoundary>2026-03-30T20:21:53Z</StartBoundary>\r\n      <Enabled>true</Enabled>\r\n      <ScheduleByDay>\r\n        <DaysInterval>1</DaysInterval>\r\n      </ScheduleByDay>\r\n    </CalendarTrigger>\r\n  </Triggers>\r\n  <Principals>\r\n    <Principal id="NetworkService">\r\n      <UserId>S-1-5-20</UserId>\r\n      <RunLevel>LeastPrivilege</RunLevel>\r\n    </Principal>\r\n  </Principals>\r\n  <Settings>\r\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\r\n    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\r\n    <AllowHardTerminate>false</AllowHardTerminate>\r\n    <StartWhenAvailable>true</StartWhenAvailable>\r\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n    <IdleSettings>\r\n      <StopOnIdleEnd>true</StopOnIdleEnd>\r\n      <RestartOnIdle>false</RestartOnIdle>\r\n    </IdleSettings>\r\n    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n    <Enabled>true</Enabled>\r\n    <Hidden>true</Hidden>\r\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>\r\n    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>\r\n    <WakeToRun>false</WakeToRun>\r\n    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n    <Priority>7</Priority>\r\n    <RestartOnFailure>\r\n      <Interval>PT1M</Interval>\r\n      <Count>3</Count>\r\n    </RestartOnFailure>\r\n  </Settings>\r\n  <Actions Context="NetworkService">\r\n    <ComHandler>\r\n      <ClassId>{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}</ClassId>\r\n      <Data><![CDATA[timer]]></Data>\r\n    </ComHandler>\r\n  </Actions>\r\n</Task>\r\n\r\nOther Information:\r\n\tProcessCreationTime: \t\t2251799813685332\r\n\tClientProcessId: \t\t\t4804\r\n\tParentProcessId: \t\t\t1116\r\n\tFQDN: \t\t0\r\n\t', 
            'event_data': {
                'SubjectDomainName': 'WORKGROUP', 
                'SubjectLogonId': '0x3e4', 
                'SubjectUserSid': 'S-1-5-20', 
                'ClientProcessStartKey': '2251799813685332', 
                'FQDN': 'server', 
                'ParentProcessId': '1116', 
                'SubjectUserName': 'SERVER$', 
                'RpcCallClientLocality': '0', 
                'ClientProcessId': '4804', 
                'TaskName': '\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask', 
                'TaskContentNew': '<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n  <RegistrationInfo>\n    <Source>$(@%systemroot%\\system32\\sppc.dll,-200)</Source>\n    <Author>$(@%systemroot%\\system32\\sppc.dll,-200)</Author>\n    <Version>1.0</Version>\n    <Description>$(@%systemroot%\\system32\\sppc.dll,-201)</Description>\n    <URI>\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask</URI>\n    <SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-123231216-2592883651-3715271367-3753151631-4175906628)(A;;FR;;;S-1-5-87-2912274048-3994893941-1669128114-1310430903-1263774323)</SecurityDescriptor>\n  </RegistrationInfo>\n  <Triggers>\n    <CalendarTrigger>\n      <StartBoundary>2026-03-30T20:21:53Z</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n    </CalendarTrigger>\n  </Triggers>\n  <Principals>\n    <Principal id="NetworkService">\n      <UserId>S-1-5-20</UserId>\n      <RunLevel>LeastPrivilege</RunLevel>\n    </Principal>\n  </Principals>\n  <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n    <AllowHardTerminate>false</AllowHardTerminate>\n    <StartWhenAvailable>true</StartWhenAvailable>\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n    <IdleSettings>\n      <StopOnIdleEnd>true</StopOnIdleEnd>\n      <RestartOnIdle>false</RestartOnIdle>\n    </IdleSettings>\n    <AllowStartOnDemand>true</AllowStartOnDemand>\n    <Enabled>true</Enabled>\n    <Hidden>true</Hidden>\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>\n    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>\n    <WakeToRun>false</WakeToRun>\n    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n    <Priority>7</Priority>\n    <RestartOnFailure>\n      <Interval>PT1M</Interval>\n      <Count>3</Count>\n    </RestartOnFailure>\n  </Settings>\n  <Actions Context="NetworkService">\n    <ComHandler>\n      <ClassId>{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}</ClassId>\n      <Data><![CDATA[timer]]></Data>\n    </ComHandler>\n  </Actions>\n</Task>'}, 
                'time_created': '2026-03-29T20:22:53Z'
                }
        """
        ed = raw.get('event_data', {})
        task_name = self._clean(ed.get('TaskName'))
        task_details = _extract_task_details(ed.get('TaskContentNew'))
        executable = task_details["command"] or task_details["com_class"]
        process_args = task_details["arguments"].split() if task_details["arguments"] else None

        return NormalizedEvent(
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
                name=self._clean(ed.get('SubjectUserName')),
                domain=self._clean(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid'))
            ),
            host=HostFields(
                hostname=self._clean(ed.get('FQDN'))
            ),
            process=ProcessFields(
                pid=int(ed.get('ClientProcessId')) if self._clean(ed.get('ClientProcessId', '')) else None,
                executable=executable,
                args=process_args,
                command_line=task_name,
                parent=ProcessFields(
                    pid=int(ed.get('ParentProcessId')) if self._clean(ed.get('ParentProcessId', '')) else None
                )
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            )
        )
    
    def _parse_4698(self, raw: dict) -> NormalizedEvent:
        """
        Event ID 4698: A scheduled task was created. Example:
         {
          "event_id": 4698,
          "message": "A scheduled task was created.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-328477448-1921108719-1792717717-1002\r\n\tAccount Name:\t\tadmin\r\n\tAccount Domain:\t\twinmachine\r\n\tLogon ID:\t\t0xA924D\r\n\r\nTask Information:\r\n\tTask Name: \t\t\\SoftLanding\\S-1-5-21-328477448-1921108719-1792717717-1002\\SoftLandingCreativeManagementTask\r\n\tTask Content: \t\t<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.6\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <Principals>\r\n    <Principal id=\"Author\">\r\n      <UserId>S-1-5-21-328477448-1921108719-1792717717-1002</UserId>\r\n      <RunLevel>LeastPrivilege</RunLevel>\r\n      <LogonType>InteractiveToken</LogonType>\r\n    </Principal>\r\n  </Principals>\r\n  <Settings>\r\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n    <AllowHardTerminate>true</AllowHardTerminate>\r\n    <StartWhenAvailable>true</StartWhenAvailable>\r\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n    <Enabled>true</Enabled>\r\n    <Hidden>false</Hidden>\r\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n    <WakeToRun>false</WakeToRun>\r\n    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>\r\n    <Priority>7</Priority>\r\n    <RestartOnFailure>\r\n      <Interval>PT4H</Interval>\r\n      <Count>5</Count>\r\n    </RestartOnFailure>\r\n  </Settings>\r\n  <Triggers>\r\n    <WnfStateChangeTrigger>\r\n      <Enabled>true</Enabled>\r\n      <StateName>7550b9a33e06830d</StateName>\r\n    </WnfStateChangeTrigger>\r\n    <TimeTrigger>\r\n      <StartBoundary>2026-05-05T11:51:00Z</StartBoundary>\r\n      <Enabled>true</Enabled>\r\n    </TimeTrigger>\r\n    <TimeTrigger>\r\n      <StartBoundary>2026-05-05T21:08:09Z</StartBoundary>\r\n      <Enabled>true</Enabled>\r\n      <Repetition>\r\n        <Interval>PT24H</Interval>\r\n        <StopAtDurationEnd>false</StopAtDurationEnd>\r\n      </Repetition>\r\n    </TimeTrigger>\r\n  </Triggers>\r\n  <Actions Context=\"Author\">\r\n    <ComHandler>\r\n      <ClassId>{F576B2F9-7850-4226-ADB0-E5993FED4F02}</ClassId>\r\n    </ComHandler>\r\n  </Actions>\r\n  <RegistrationInfo>\r\n    <URI>\\SoftLanding\\S-1-5-21-328477448-1921108719-1792717717-1002\\SoftLandingCreativeManagementTask</URI>\r\n    <SecurityDescriptor>D:P(A;;FA;;;SY)(A;CI;0x80010000;;;WD)(A;;FA;;;S-1-5-21-328477448-1921108719-1792717717-1002)</SecurityDescriptor>\r\n  </RegistrationInfo>\r\n</Task>\r\n\r\nOther Information:\r\n\tProcessCreationTime: \t\t1970324836974733\r\n\tClientProcessId: \t\t\t7024\r\n\tParentProcessId: \t\t\t1284\r\n\tFQDN: \t\t0\r\n\t",
          "event_data": {
            "SubjectDomainName": "winmachine",
            "SubjectLogonId": "0xa924d",
            "SubjectUserSid": "S-1-5-21-328477448-1921108719-1792717717-1002",
            "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.6\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  <Principals>\n    <Principal id=\"Author\">\n      <UserId>S-1-5-21-328477448-1921108719-1792717717-1002</UserId>\n      <RunLevel>LeastPrivilege</RunLevel>\n      <LogonType>InteractiveToken</LogonType>\n    </Principal>\n  </Principals>\n  <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n    <AllowHardTerminate>true</AllowHardTerminate>\n    <StartWhenAvailable>true</StartWhenAvailable>\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n    <AllowStartOnDemand>true</AllowStartOnDemand>\n    <Enabled>true</Enabled>\n    <Hidden>false</Hidden>\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n    <WakeToRun>false</WakeToRun>\n    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>\n    <Priority>7</Priority>\n    <RestartOnFailure>\n      <Interval>PT4H</Interval>\n      <Count>5</Count>\n    </RestartOnFailure>\n  </Settings>\n  <Triggers>\n    <WnfStateChangeTrigger>\n      <Enabled>true</Enabled>\n      <StateName>7550b9a33e06830d</StateName>\n    </WnfStateChangeTrigger>\n    <TimeTrigger>\n      <StartBoundary>2026-05-05T11:51:00Z</StartBoundary>\n      <Enabled>true</Enabled>\n    </TimeTrigger>\n    <TimeTrigger>\n      <StartBoundary>2026-05-05T21:08:09Z</StartBoundary>\n      <Enabled>true</Enabled>\n      <Repetition>\n        <Interval>PT24H</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>\n      </Repetition>\n    </TimeTrigger>\n  </Triggers>\n  <Actions Context=\"Author\">\n    <ComHandler>\n      <ClassId>{F576B2F9-7850-4226-ADB0-E5993FED4F02}</ClassId>\n    </ComHandler>\n  </Actions>\n  <RegistrationInfo>\n    <URI>\\SoftLanding\\S-1-5-21-328477448-1921108719-1792717717-1002\\SoftLandingCreativeManagementTask</URI>\n    <SecurityDescriptor>D:P(A;;FA;;;SY)(A;CI;0x80010000;;;WD)(A;;FA;;;S-1-5-21-328477448-1921108719-1792717717-1002)</SecurityDescriptor>\n  </RegistrationInfo>\n</Task>",
            "FQDN": "winmachine",
            "ParentProcessId": "1284",
            "SubjectUserName": "admin",
            "RpcCallClientLocality": "0",
            "ClientProcessId": "7024",
            "TaskName": "\\SoftLanding\\S-1-5-21-328477448-1921108719-1792717717-1002\\SoftLandingCreativeManagementTask",
            "ClientProcessStartKey": "1970324836974733"
          },
          "time_created": "2026-05-05T11:21:15Z"
        },
        """
        ed = raw.get('event_data', {})
        task_name = self._clean(ed.get('TaskName'))
        
        task_details = _extract_task_details(ed.get('TaskContent'))
        executable = task_details["command"] or task_details["com_class"]
        process_args = task_details["arguments"].split() if task_details["arguments"] else None

        is_system_path = task_name and any(
            task_name.startswith(p) for p in [
                "\\Microsoft\\", "\\Windows\\"
            ]
        )
        uses_com_handler = task_details["com_class"] is not None
        is_hidden = task_details.get("hidden", False)

        if uses_com_handler and not is_system_path:
            severity = 4  
        elif not is_system_path or is_hidden:
            severity = 3
        else:
            severity = 1 

        return NormalizedEvent(
            event=EventFields(
                action="scheduled_task_created",
                category="persistence",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=severity,
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._clean(ed.get('SubjectUserName')),
                domain=self._clean(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid'))
            ),
            host=HostFields(
                hostname=self._clean(ed.get('FQDN'))
            ),
            process=ProcessFields(
                pid=int(ed.get('ClientProcessId')) if self._clean(ed.get('ClientProcessId', '')) else None,
                executable=executable,
                args=process_args,
                command_line=task_name,
                parent=ProcessFields(
                    pid=int(ed.get('ParentProcessId')) if self._clean(ed.get('ParentProcessId', '')) else None
                )
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
                extra={
                    "task_name": task_name,
                    "uses_com_handler": uses_com_handler,
                    "com_class": task_details["com_class"],
                    "is_hidden": is_hidden,
                }
            )
        )

    def _parse_4720(self, raw: dict) -> NormalizedEvent:
        """
        Event ID 4720: A user account was created. Example:
        {
          "event_id": 4720,
          "message": "A user account was created.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWINMACHINE$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nNew Account:\r\n\tSecurity ID:\t\tS-1-5-21-328477448-1921108719-1792717717-1003\r\n\tAccount Name:\t\tattacker\r\n\tAccount Domain:\t\twinmachine\r\n\r\nAttributes:\r\n\tSAM Account Name:\tattacker\r\n\tDisplay Name:\t\t<value not set>\r\n\tUser Principal Name:\t-\r\n\tHome Directory:\t\t<value not set>\r\n\tHome Drive:\t\t<value not set>\r\n\tScript Path:\t\t<value not set>\r\n\tProfile Path:\t\t<value not set>\r\n\tUser Workstations:\t<value not set>\r\n\tPassword Last Set:\t<never>\r\n\tAccount Expires:\t\t<never>\r\n\tPrimary Group ID:\t513\r\n\tAllowed To Delegate To:\t-\r\n\tOld UAC Value:\t\t0x0\r\n\tNew UAC Value:\t\t0x15\r\n\tUser Account Control:\t\r\n\t\tAccount Disabled\r\n\t\t'Password Not Required' - Enabled\r\n\t\t'Normal Account' - Enabled\r\n\tUser Parameters:\t<value not set>\r\n\tSID History:\t\t-\r\n\tLogon Hours:\t\tAll\r\n\r\nAdditional Information:\r\n\tPrivileges\t\t-",
          "event_data": {
            "HomePath": "%%1793",
            "SubjectUserName": "WINMACHINE$",
            "NewUacValue": "0x15",
            "UserPrincipalName": "-",
            "SubjectLogonId": "0x3e7",
            "DisplayName": "%%1793",
            "ProfilePath": "%%1793",
            "UserAccountControl": "\n\t\t%%2080\n\t\t%%2082\n\t\t%%2084",
            "PrivilegeList": "-",
            "SamAccountName": "attacker",
            "UserParameters": "%%1793",
            "AllowedToDelegateTo": "-",
            "LogonHours": "%%1797",
            "SubjectUserSid": "S-1-5-18",
            "ScriptPath": "%%1793",
            "HomeDirectory": "%%1793",
            "OldUacValue": "0x0",
            "AccountExpires": "%%1794",
            "PrimaryGroupId": "513",
            "SubjectDomainName": "WORKGROUP",
            "UserWorkstations": "%%1793",
            "TargetSid": "S-1-5-21-328477448-1921108719-1792717717-1003",
            "PasswordLastSet": "%%1794",
            "SidHistory": "-",
            "TargetDomainName": "winmachine",
            "TargetUserName": "attacker"
          },
          "time_created": "2026-05-05T12:29:18Z"
        },
        """
        ed = raw.get('event_data', {})
        return NormalizedEvent(
            event=EventFields(
                action="user_account_created",
                category="iam",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=3,  # account creation e întotdeauna notabil
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                # target = contul nou creat, mai relevant decât subiectul
                name=self._clean(ed.get('TargetUserName')),
                domain=self._clean(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetSid'))
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            )
    )

    def _parse_4732(self, raw: dict) -> NormalizedEvent:
        """
        Event ID 4732: A member was added to a security-enabled local group. Example:
        {
          "event_id": 4732,
          "message": "A member was added to a security-enabled local group.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWINMACHINE$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nMember:\r\n\tSecurity ID:\t\tS-1-5-21-328477448-1921108719-1792717717-1003\r\n\tAccount Name:\t\t-\r\n\r\nGroup:\r\n\tSecurity ID:\t\tS-1-5-32-544\r\n\tGroup Name:\t\tAdministrators\r\n\tGroup Domain:\t\tBuiltin\r\n\r\nAdditional Information:\r\n\tPrivileges:\t\t-",
          "event_data": {
            "SubjectDomainName": "WORKGROUP",
            "TargetUserName": "Administrators",
            "SubjectUserSid": "S-1-5-18",
            "PrivilegeList": "-",
            "TargetSid": "S-1-5-32-544",
            "MemberSid": "S-1-5-21-328477448-1921108719-1792717717-1003",
            "SubjectLogonId": "0x3e7",
            "SubjectUserName": "WINMACHINE$",
            "MemberName": "-",
            "TargetDomainName": "Builtin"
          },
          "time_created": "2026-05-05T12:29:18Z"
        },
        """
        ed = raw.get('event_data', {})

        group_name = self._clean(ed.get('TargetUserName'))
        is_admin_group = group_name and group_name.lower() == "administrators"

        return NormalizedEvent(
            event=EventFields(
                action="user_added_to_group",
                category="iam",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows_security",
                module="windows",
                severity=4 if is_admin_group else 2, 
                original=raw.get('message', '').encode('utf-8'),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._clean(ed.get('SubjectUserName')),
                domain=self._clean(ed.get('SubjectDomainName')),
                id=self._clean(ed.get('SubjectUserSid'))
            ),
            group=GroupFields(
                name=group_name,
                domain=self._clean(ed.get('TargetDomainName')),
                id=self._clean(ed.get('TargetSid')),
                member_id=self._clean(ed.get('MemberSid')),
                member_name=self._clean(ed.get('MemberName')),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=raw.get('event_id'),
                provider_name="Microsoft-Windows-Security-Auditing",
            )
        )