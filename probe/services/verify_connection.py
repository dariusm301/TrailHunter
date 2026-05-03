import socket

def verify_internet_connection():
    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=5):
            return {"status": "ok"}
    except socket.error:
        return {"status": "error"}
    

def verify_analysis_server_connection(analysis_server_url):
    try:
        host, port = analysis_server_url.replace("http://", "").split(":")
        with socket.create_connection((host, int(port)), timeout=5):
            return {"status": "ok"}
    except socket.error:
        return {"status": "error"}
    

print(verify_analysis_server_connection("localhost:80"))