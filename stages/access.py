import requests
import subprocess
from services.BruteForceDVWA import BruteForceDVWA
from config import *
import os

class Access:
    
    def __init__(self, username_wordlist = None, password_wordlist = None, url = None, session = requests.Session()):
        self.brute_force = BruteForceDVWA(username_wordlist=username_wordlist, password_wordlist=password_wordlist, url=url, session=session)
        self.session = session
    def brute_force_login(self):
        if self.brute_force.username_wordlist is None or self.brute_force.password_wordlist is None:
            raise ValueError("Username and password wordlists must be provided.")
        if self.brute_force.url is None:
            raise ValueError("URL must be provided.") 
        return self.brute_force.brute_force_login()
    
    def login(self , username: str, password: str, url: str):
        login_page = self.session.get(url)
        user_token = self.brute_force.find_user_token(login_page.text)
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
            self.brute_force.set_security_level(level='high', url=DVWA_SECURITY_LEVEL_URL)
            print("Logged in successfully and security level set to high.")
        return response