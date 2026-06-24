import asyncio


async def configure_wifi(ssid: str, password: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "sudo", "/usr/local/bin/wifi_helper", ssid,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate(input=(password + "\n").encode())

    if proc.returncode != 0:
        return {"success": False, "error": stderr.decode().strip() or "unknown error"}

    return {"success": True}
