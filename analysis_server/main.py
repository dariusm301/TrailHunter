import fastapi
from routes import detection, correlate, ingest
import uvicorn
from config import settings

app = fastapi.FastAPI()

app.include_router(ingest.router)
app.include_router(detection.router)
app.include_router(correlate.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
