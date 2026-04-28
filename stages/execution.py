

class Execution():
    def __init__(self, session = None):
        self.session = session

    def execute_command(self, command, url):
        if self.session is None:
            raise ValueError("Session must be provided.")
        response = self.session.get(url, params={'cmd': command})
        start = response.text.find("<output>") + len("<output>")
        end = response.text.find("</output>")
        return response.text[start:end]