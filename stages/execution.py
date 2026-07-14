

class Execution():
    def __init__(self, session = None):
        self.session = session

    def execute_command_get(self, command, url, param):
        if self.session is None:
            raise ValueError("Session must be provided.")
        response = self.session.get(url, params={param: command})
        start = response.text.find("<output>") + len("<output>")
        end = response.text.find("</output>")
        return response.text[start:end]
    
    def execute_command_post(self, command, url):
        response = self.session.post(url, data={
            "ip": command,
            "Submit": "Submit"
        })
        return response.text