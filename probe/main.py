from fastapi import FastAPI
from routes import serve_scripts, ingest, control, client_socket
import uvicorn
from logging_config import setup_logging

app = FastAPI(title="Probe")

app.include_router(ingest.router)
app.include_router(serve_scripts.router)
app.include_router(control.router)
app.include_router(client_socket.router)
if __name__ == "__main__":
    uvicorn.run("main:app", host = "0.0.0.0", port=8000, reload=True, ws_ping_interval=None, ws_ping_timeout=None)







