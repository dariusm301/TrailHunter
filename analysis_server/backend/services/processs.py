import json
from normalizers.base import BaseNormalizer
from services.storage import CollectionStorage
from normalizers.windows.wmi import WMINormalizer
from normalizers.windows.security import SecurityNormalizer
from normalizers.windows.sysmon import SysmonNormalizer
from normalizers.windows.application import ApplicationNormalizer
from normalizers.windows.system import SystemNormalizer
from normalizers.windows.powershell import PowerShellNormalizer
from normalizers.windows.network import NetworkNormalizer
from normalizers.windows.processes import ProcessesNormalizer
from normalizers.windows.registry import RegistryNormalizer
from normalizers.windows.scheduled_tasks import ScheduledTasksNormalizer
from normalizers.apache import ApacheNormalizer
from normalizers.helpers.probe_ip import _resolve_probe_ips

def process_collection(storage: CollectionStorage):
    raw_data = storage.load_raw()

    payload = json.loads(raw_data.decode("utf-8"))

    hostname = payload['metadata']['hostname']
    collected_at = payload['metadata']['collected_at']
    os_version = payload['metadata']['os_version']
    
    summary = storage.load_summary()
    probe_ips = _resolve_probe_ips(summary)
    try:
        wmi_normalizer = WMINormalizer()
        wmi_events = payload.get('modules').get('event_logs').get('wmi', [])
        wmi_events_normalized = []
        if wmi_events:
            for event in wmi_events:
                normalized_event = wmi_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    wmi_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize WMI event: {event}")
            storage.save_channel('wmi', wmi_events_normalized)
        

        security_events = payload.get('modules').get('event_logs').get('security', [])
        security_events_normalized = []
        if security_events:
            security_normalizer = SecurityNormalizer()
            for event in security_events:
                normalized_event = security_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    security_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize Security event: {event.get('event_id')}")
            storage.save_channel('security', security_events_normalized)

        sysmon_events = payload.get('modules').get('event_logs').get('sysmon', [])
        sysmon_events_normalized = []
        if sysmon_events:
            sysmon_normalizer = SysmonNormalizer()
            for event in sysmon_events:
                normalized_event = sysmon_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    sysmon_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize Sysmon event: {event.get('event_id')}")
            storage.save_channel('sysmon', sysmon_events_normalized)

        application_events = payload.get('modules').get('event_logs').get('application', [])
        application_events_normalized = []
        if application_events:
            application_normalizer = ApplicationNormalizer()
            for event in application_events:
                normalized_event = application_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    application_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize Application event: {event.get('event_id')}")
            storage.save_channel('application', application_events_normalized)

        system_events = payload.get('modules').get('event_logs').get('system', [])
        system_events_normalized = []
        if system_events:
            system_normalizer = SystemNormalizer()
            for event in system_events:
                normalized_event = system_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    system_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize System event: {event.get('event_id')}")
            storage.save_channel('system', system_events_normalized)

        powershell_events = payload.get('modules').get('event_logs').get('powershell', [])
        powershell_events_normalized = []
        if powershell_events:
            powershell_normalizer = PowerShellNormalizer()
            for event in powershell_events:
                normalized_event = powershell_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    powershell_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize PowerShell event: {event.get('event_id')}")
            storage.save_channel('powershell', powershell_events_normalized)

        processes_events = payload.get('modules').get('processes').get('processes', [])
        processes_events_normalized = []
        if processes_events:
            processes_normalizer = ProcessesNormalizer()
            for event in processes_events:
                normalized_event = processes_normalizer.normalize(event)
                if normalized_event is not None:
                    normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                    processes_events_normalized.append(normalized_event)
                else:
                    print(f"Failed to normalize Processes event: {event}")
            storage.save_channel('processes', processes_events_normalized)
            

        network_events = payload.get('modules').get('network', [])
        network_events_normalized = []
        if network_events:
            network_normalizer = NetworkNormalizer()
            for event_type in network_events:
                if network_events[event_type] != None:
                    if isinstance(network_events[event_type], list):
                        for event in network_events[event_type]:
                            normalized_event = network_normalizer.normalize(event, event_type)
                            if normalized_event is not None:
                                normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                                network_events_normalized.append(normalized_event)
                            else:
                                print(f"Failed to normalize Network event: {event}")
                    else:
                        normalized_event = network_normalizer.normalize(network_events[event_type], event_type)
                        if normalized_event is not None:
                            normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                            network_events_normalized.append(normalized_event)
                        else:
                            print(f"Failed to normalize Network event: {network_events[event_type]}")
            storage.save_channel('network', network_events_normalized)

        registry_events = payload.get('modules').get('registry').get('data', [])
        registry_events_normalized = []
        if registry_events:
            registry_normalizer = RegistryNormalizer()
            for registry_key in registry_events:
                if isinstance(registry_events[registry_key], list):
                    for registry_event in registry_events[registry_key]:
                        normalized_event = registry_normalizer.normalize(registry_event, registry_key)
                        if normalized_event is not None:
                            normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                            registry_events_normalized.append(normalized_event)
                else:
                    if registry_events[registry_key] is not None:
                        normalized_event = registry_normalizer.normalize(registry_events[registry_key], registry_key)
                        if normalized_event is not None:
                            normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                            registry_events_normalized.append(normalized_event)
            storage.save_channel('registry', registry_events_normalized)

        scheduled_tasks_events = payload.get('modules').get('scheduled_tasks').get('tasks', [])
        scheduled_tasks_events_normalized = []
        if scheduled_tasks_events:
            scheduled_tasks_normalizer = ScheduledTasksNormalizer()
            for event in scheduled_tasks_events:
                normalized_event = scheduled_tasks_normalizer.normalize(event)
                if normalized_event is not None: 
                    for ne in normalized_event:
                        ne.is_probe = BaseNormalizer._is_probe(ne, probe_ips)
                    scheduled_tasks_events_normalized.extend(normalized_event)
                else:
                    print(f"Failed to normalize Scheduled Task event: {event}")

            storage.save_channel('scheduled_tasks', scheduled_tasks_events_normalized)

        apache_logs = payload.get('modules').get('web_logs').get('data', [])
        apache_logs_normalized = []
        if apache_logs:
            apache_normalizer = ApacheNormalizer()
            for event_type in apache_logs:
                events = apache_logs[event_type].get('entries', [])
                for event in events:
                    normalized_event = apache_normalizer.normalize(event, event_type)
                    if normalized_event is not None:
                        normalized_event.is_probe = BaseNormalizer._is_probe(normalized_event, probe_ips)
                        apache_logs_normalized.append(normalized_event)
                    else:
                        print(f"Failed to normalize Apache log event: {event}")
            storage.save_channel('web_logs', apache_logs_normalized)

        print(summary)

        storage.save_summary(
            {
                "hostname": hostname,
                "collected_at": collected_at,
                "os_version": os_version,
                "collector_ip": summary.get("collector_ip", {}),
                "event_counts": {
                    "wmi": len(wmi_events_normalized),
                    "security": len(security_events_normalized),
                    "sysmon": len(sysmon_events_normalized),
                    "application": len(application_events_normalized),
                    "system": len(system_events_normalized),
                    "powershell": len(powershell_events_normalized),
                    "processes": len(processes_events_normalized),
                    "network": len(network_events_normalized),
                    "registry": len(registry_events_normalized),
                    "scheduled_tasks": len(scheduled_tasks_events_normalized),
                    "web_logs": len(apache_logs_normalized)
                },
                "hashes": 
                    payload.get('module_hashes', {}),           
            }
        )
    except Exception as e:
        print(f"Error processing collection: {e}")
