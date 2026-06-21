from fastapi import FastAPI
from config import settings
from probe.routes import ingest
from routes import serve_scripts
import uvicorn

app = FastAPI(title="Probe")

app.include_router(ingest.router)
app.include_router(serve_scripts.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host = settings.host, port=settings.port, reload=True)







