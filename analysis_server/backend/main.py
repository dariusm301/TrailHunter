from routes import correlate, detection, collections, ingest
import fastapi
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from config import settings

app = fastapi.FastAPI()

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

if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
