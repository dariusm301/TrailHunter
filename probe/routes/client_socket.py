from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter()

@router.get("/client_socket.ps1", response_class=PlainTextResponse)
async def get_client_socket_script():
    return open("scripts/client_socket.ps1").read()
