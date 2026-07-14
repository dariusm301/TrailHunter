TARGET_IP = "172.28.195.108"
TARGET_PORT = 80
ATTACKER_IP = "172.28.192.211"
SHELL_PORT = 8000


NEW_USER = "attacker2"
NEW_USER_PASSWORD = "att2_pass"


USERNAME_WORDLIST = "wordlists/usernames.txt"
PASSWORD_WORDLIST = "wordlists/passwords.txt"

DVWA_BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}/"
DVWA_LOGIN_URL = DVWA_BASE_URL + "login.php"
DVWA_FILE_UPLOAD_URL = DVWA_BASE_URL + "vulnerabilities/upload/"
DVWA_SECURITY_LEVEL_URL = DVWA_BASE_URL + "security.php"

DVWA_COMMAND_INJECTION = f"http://{TARGET_IP}:{TARGET_PORT}/vulnerabilities/exec/"

