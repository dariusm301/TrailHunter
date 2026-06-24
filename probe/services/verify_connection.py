import socket

def verify_internet_connection():
    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=5):
            return {"status": "ok"}
    except socket.error:
        return {"status": "error"}
    


