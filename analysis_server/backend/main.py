from routes import correlate, detection, collections, ingest, auth, ingest_probe, probe_tokens, users, serve_scripts
import fastapi
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from config import settings
from services.database import Base, engine

app = fastapi.FastAPI()

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(detection.router)
app.include_router(correlate.router)
app.include_router(collections.router)
app.include_router(auth.router)
app.include_router(ingest_probe.router)
app.include_router(probe_tokens.router)
app.include_router(users.router)
app.include_router(serve_scripts.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
