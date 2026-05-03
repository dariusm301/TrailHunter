import fastapi
from routes import collect
import uvicorn
from config import settings

app = fastapi.FastAPI()

app.include_router(collect.router)
if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
